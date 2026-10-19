#include "WindowsOperations.h"
#ifdef WINDOWS
#include <Windows.h>
#include <filesystem>
#include <stdexcept>
#include "LocalShell.h"
#include "WindowsProvider.h"
#include "platform/PlatformHelper.h"
#include "storage/AppSettings.h"
#include "utils/StringUtils.h"
#include "../../../desktop/src/installer/WinFirewallHelper.h"

namespace {
const std::wstring Guid = L"{74A23DE2-B81D-46EC-E129-CD32507ED716}";
std::filesystem::path Root(bool legacy = false) {
  return PlatformHelper::GetSystemDataDir() / (legacy ? "PCBioUnlock" : "PulseUnlock");
}
bool Same(const std::filesystem::path &a, const std::filesystem::path &b) {
  return _wcsicmp(a.lexically_normal().c_str(), b.lexically_normal().c_str()) == 0;
}
bool SafePath(const std::filesystem::path &p) {
  if(!p.is_absolute() || p != p.lexically_normal()) return false;
  for(auto cur = p; !cur.empty();) {
    const auto attr = GetFileAttributesW(cur.c_str());
    if(attr != INVALID_FILE_ATTRIBUTES && (attr & FILE_ATTRIBUTE_REPARSE_POINT)) return false;
    if(cur == cur.root_path()) break;
    cur = cur.parent_path();
  }
  return true;
}
bool StoragePath(const std::filesystem::path &p, bool directory = false, bool logs = false) {
  if(!SafePath(p)) return false;
  for(bool legacy : {false, true}) {
    auto root = Root(legacy);
    if(directory && Same(p, root)) return true;
    if(Same(p.parent_path(), root)) {
      const auto n = p.filename().wstring();
      if(n == L"app_settings.json" || n == L"paired_devices.json" || n == L"LOG_DEBUG") return true;
    }
    if(logs && Same(p.parent_path(), root / "logs")) {
      const auto n = p.filename().wstring();
      if(n == L"module.log" || n == L"elevator.log" || n == L"desktop.log") return true;
    }
  }
  return false;
}
bool Provider(bool install) { return install ? WindowsProvider::Install() : WindowsProvider::Remove(); }

}

bool WindowsOperations::IsProviderInstalled() { return WindowsProvider::IsInstalled(); }

bool WindowsOperations::ValidateCommand(const ElevatorCommand &c) {
  if(c.dataBytes.size() > 4*1024*1024) return false;
  switch(c.type) {
    case ElevatorCommandType::INSTALL_PROVIDER:
    case ElevatorCommandType::REMOVE_PROVIDER:
    case ElevatorCommandType::CONFIGURE_FIREWALL:
    case ElevatorCommandType::REMOVE_FIREWALL:
    case ElevatorCommandType::MIGRATE_STORAGE:
    case ElevatorCommandType::IS_PROVIDER_INSTALLED:
      return c.args.empty() && c.dataBytes.empty();
    case ElevatorCommandType::READ_BYTES:
      return c.args.size()==1 && c.dataBytes.empty() && StoragePath(c.args[0], false, true);
    case ElevatorCommandType::EXISTS:
      return c.args.size()==1 && c.dataBytes.empty() && StoragePath(c.args[0], true, true);
    case ElevatorCommandType::WRITE_ATOMIC:
      return c.args.size()==1 && StoragePath(c.args[0]);
    case ElevatorCommandType::CREATE_FILE:
      return c.args.size()==2 && c.dataBytes.empty() &&
        ((c.args[1]=="true" && (Same(c.args[0],Root()) || Same(c.args[0],Root(true))) && SafePath(c.args[0])) ||
         (c.args[1]=="false" && StoragePath(c.args[0]) && std::filesystem::path(c.args[0]).filename()=="LOG_DEBUG"));
    case ElevatorCommandType::REMOVE:
      return c.args.size()==2 && c.args[1]=="false" && c.dataBytes.empty() && StoragePath(c.args[0]) && std::filesystem::path(c.args[0]).filename()=="LOG_DEBUG";
    case ElevatorCommandType::PROTECT_FILE:
      return c.args.size()==2 && c.args[1]=="true" && c.dataBytes.empty() && StoragePath(c.args[0], true);
    default: return false; // RUN_CMD and generic WRITE_BYTES are forbidden on Windows.
  }
}
ElevatorCommandResponse WindowsOperations::Execute(const ElevatorCommand &c) {
  LocalShell::ClearOperationError();
  const auto response=[](bool ok) {
    auto detail = LocalShell::GetOperationError();
    return ElevatorCommandResponse(!ok, ok ? "" : (detail.empty() ? "Stage=operation, Code=31" : detail));
  };
  try {
    if(!LocalShell::IsRunningAsAdmin() || !ValidateCommand(c)) return ElevatorCommandResponse(true,"Operation denied.");
    switch(c.type) {
      case ElevatorCommandType::IS_PROVIDER_INSTALLED: {
        const bool installed=IsProviderInstalled();
        if(!LocalShell::GetOperationError().empty()) return response(false);
        return ElevatorCommandResponse(ShellCmdResult{installed ? 0 : 1, {}});
      }
      case ElevatorCommandType::INSTALL_PROVIDER: return response(Provider(true));
      case ElevatorCommandType::REMOVE_PROVIDER: return response(Provider(false));
      case ElevatorCommandType::CONFIGURE_FIREWALL: return response(WinFirewallHelper::ConfigureOwnedRules());
      case ElevatorCommandType::REMOVE_FIREWALL: return response(WinFirewallHelper::RemoveOwnedRules());
      case ElevatorCommandType::MIGRATE_STORAGE: {
        LocalShell::StoragePathGuard guard(Root(true));
        if(!guard.IsValid()) return response(LocalShell::FailOperation("migration.ancestry", ERROR_ACCESS_DENIED));
        // Keep legacy records in place rather than expose credentials during a directory move.
        if(!std::filesystem::is_directory(Root(true)) || !LocalShell::ProtectFile(Root(true), true)) return response(false);
        for(const auto &name : {"app_settings.json", "paired_devices.json", "LOG_DEBUG"}) {
          auto path = Root(true) / name;
          if(std::filesystem::exists(path) && (!SafePath(path) || !LocalShell::ProtectFile(path,true))) return response(false);
        }
        return response(true);
      }
      case ElevatorCommandType::EXISTS: {
        LocalShell::StoragePathGuard guard(c.args[0]);
        if(!guard.IsValid()) return response(LocalShell::FailOperation("exists.ancestry", ERROR_ACCESS_DENIED));
        return ElevatorCommandResponse(ShellCmdResult{std::filesystem::exists(c.args[0])?0:1,{}});
      }
      case ElevatorCommandType::READ_BYTES: {
        LocalShell::StoragePathGuard guard(c.args[0]);
        if(!guard.IsValid()) return response(LocalShell::FailOperation("read.ancestry", ERROR_ACCESS_DENIED));
        if(!LocalShell::ProtectFile(std::filesystem::path(c.args[0]).parent_path(),true)) return response(false);
        if(std::filesystem::file_size(c.args[0]) > IPCHelper::MAX_BLOB_SIZE) return response(false);
        if(StoragePath(c.args[0]) && !LocalShell::ProtectFile(c.args[0],true)) return response(false);
        return ElevatorCommandResponse(LocalShell::ReadBytes(c.args[0]));
      }
      case ElevatorCommandType::WRITE_ATOMIC: return response(LocalShell::WriteBytesAtomic(c.args[0], c.dataBytes));
      case ElevatorCommandType::CREATE_FILE: return response(c.args[1]=="true" ? LocalShell::CreateDir(c.args[0]) && LocalShell::ProtectFile(c.args[0],true) : LocalShell::WriteBytesAtomic(c.args[0],{}));
      case ElevatorCommandType::REMOVE: {
        const std::filesystem::path path(c.args[0]);
        LocalShell::StoragePathGuard guard(path.parent_path());
        if(!guard.IsValid() || !LocalShell::ProtectFile(path.parent_path(),true)) return response(false);
        HANDLE file=CreateFileW(path.c_str(), DELETE | FILE_READ_ATTRIBUTES, FILE_SHARE_READ, nullptr,
                               OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
        if(file==INVALID_HANDLE_VALUE) {
          const auto error=GetLastError();
          return response(error==ERROR_FILE_NOT_FOUND || LocalShell::FailOperation("remove.open",error));
        }
        BY_HANDLE_FILE_INFORMATION info{};
        bool ok=GetFileInformationByHandle(file,&info) && info.nNumberOfLinks==1 &&
                !(info.dwFileAttributes & (FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_DIRECTORY));
        FILE_DISPOSITION_INFO disposition{TRUE};
        if(ok) ok=SetFileInformationByHandle(file,FileDispositionInfo,&disposition,sizeof(disposition))!=FALSE;
        const auto error=GetLastError();
        CloseHandle(file);
        return response(ok || LocalShell::FailOperation("remove.identity",error ? error : ERROR_ACCESS_DENIED));
      }
      case ElevatorCommandType::PROTECT_FILE: return response(LocalShell::ProtectFile(c.args[0],true));
      default: return response(false);
    }
  } catch(...) { return response(false); }
}
#endif
