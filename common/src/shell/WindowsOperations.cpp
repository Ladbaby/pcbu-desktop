#include "WindowsOperations.h"
#ifdef WINDOWS
#include <Windows.h>
#include <filesystem>
#include <stdexcept>
#include "LocalShell.h"
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
bool SetValue(const std::wstring &key, const wchar_t *name, const std::wstring &value) {
  HKEY h{};
  auto status = RegCreateKeyExW(HKEY_LOCAL_MACHINE, key.c_str(), 0, nullptr, 0, KEY_SET_VALUE | KEY_WOW64_64KEY, nullptr, &h, nullptr);
  if(status != ERROR_SUCCESS) return LocalShell::FailOperation("provider.registry_open", status);
  status = RegSetValueExW(h, name, 0, REG_SZ, reinterpret_cast<const BYTE *>(value.c_str()), static_cast<DWORD>((value.size()+1)*sizeof(wchar_t)));
  RegCloseKey(h);
  return status == ERROR_SUCCESS || LocalShell::FailOperation("provider.registry_write", status);
}
std::filesystem::path SystemDir() {
  wchar_t dir[MAX_PATH]{};
  if(!GetSystemDirectoryW(dir, MAX_PATH)) throw std::runtime_error("System directory unavailable.");
  return dir;
}
bool Provider(bool install) {
  const auto cls = L"SOFTWARE\\Classes\\CLSID\\" + Guid;
  const auto registration = L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Authentication\\Credential Providers\\" + Guid;
  auto target = SystemDir() / "win_pulseunlock.dll";
  if(!SafePath(target)) return false;
  if(!install) {
    for(const auto &key : {registration, cls}) {
      const auto result = RegDeleteTreeW(HKEY_LOCAL_MACHINE, key.c_str());
      if(result != ERROR_SUCCESS && result != ERROR_FILE_NOT_FOUND) return false;
    }
    for(const auto &name : {"win_pulseunlock.dll", "win-pcbiounlock.dll"}) {
      auto file = SystemDir() / name;
      if(!SafePath(file)) return false;
      if(!DeleteFileW(file.c_str()) && GetLastError() != ERROR_FILE_NOT_FOUND) return false;
    }
    return true;
  }
  // Install only the provider embedded at build time, never caller-supplied bytes or paths.
  auto resource = FindResourceW(nullptr, MAKEINTRESOURCEW(101), MAKEINTRESOURCEW(10));
  if(!resource) return LocalShell::FailOperation("provider.resource", GetLastError());
  auto data = LoadResource(nullptr, resource);
  const auto size = SizeofResource(nullptr, resource);
  auto bytes = static_cast<const uint8_t *>(LockResource(data));
  if(!bytes || !size) return LocalShell::FailOperation("provider.resource_data", ERROR_RESOURCE_DATA_NOT_FOUND);
  const auto suffix = StringUtils::RandomString(24, false);
  if(suffix.empty()) return LocalShell::FailOperation("provider.random", ERROR_GEN_FAILURE);
  auto temporary = SystemDir() / (".pcbu-provider-" + suffix + ".tmp");
  HANDLE file = CreateFileW(temporary.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, nullptr);
  if(file == INVALID_HANDLE_VALUE) return LocalShell::FailOperation("provider.create", GetLastError());
  DWORD written{};
  bool ok = WriteFile(file, bytes, size, &written, nullptr) != FALSE;
  if(!ok) LocalShell::FailOperation("provider.write", GetLastError());
  if(ok && written != size) ok = LocalShell::FailOperation("provider.short_write", ERROR_WRITE_FAULT);
  if(ok && !FlushFileBuffers(file)) ok = LocalShell::FailOperation("provider.flush", GetLastError());
  CloseHandle(file);
  if(ok && !MoveFileExW(temporary.c_str(),target.c_str(),MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH))
    ok = LocalShell::FailOperation("provider.replace", GetLastError());
  if(!ok) { DeleteFileW(temporary.c_str()); return false; }
  return SetValue(registration, nullptr, L"win_pulseunlock") && SetValue(cls, nullptr, L"win_pulseunlock") &&
         SetValue(cls + L"\\InprocServer32", nullptr, target.wstring()) && SetValue(cls + L"\\InprocServer32", L"ThreadingModel", L"Apartment");
}
}

bool WindowsOperations::ValidateCommand(const ElevatorCommand &c) {
  if(c.dataBytes.size() > 4*1024*1024) return false;
  switch(c.type) {
    case ElevatorCommandType::INSTALL_PROVIDER:
    case ElevatorCommandType::REMOVE_PROVIDER:
    case ElevatorCommandType::CONFIGURE_FIREWALL:
    case ElevatorCommandType::REMOVE_FIREWALL:
    case ElevatorCommandType::MIGRATE_STORAGE:
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
      case ElevatorCommandType::INSTALL_PROVIDER: return response(Provider(true));
      case ElevatorCommandType::REMOVE_PROVIDER: return response(Provider(false));
      case ElevatorCommandType::CONFIGURE_FIREWALL: return response(WinFirewallHelper::ConfigureOwnedRules());
      case ElevatorCommandType::REMOVE_FIREWALL: return response(WinFirewallHelper::RemoveOwnedRules());
      case ElevatorCommandType::MIGRATE_STORAGE:
        // Keep legacy records in place rather than expose credentials during a directory move.
        if(!std::filesystem::is_directory(Root(true)) || !LocalShell::ProtectFile(Root(true), true)) return response(false);
        for(const auto &name : {"app_settings.json", "paired_devices.json", "LOG_DEBUG"}) {
          auto path = Root(true) / name;
          if(std::filesystem::exists(path) && (!SafePath(path) || !LocalShell::ProtectFile(path,true))) return response(false);
        }
        return response(true);
      case ElevatorCommandType::EXISTS: return ElevatorCommandResponse(ShellCmdResult{std::filesystem::exists(c.args[0])?0:1,{}});
      case ElevatorCommandType::READ_BYTES: {
        if(!LocalShell::ProtectFile(std::filesystem::path(c.args[0]).parent_path(),true)) return response(false);
        if(std::filesystem::file_size(c.args[0]) > IPCHelper::MAX_BLOB_SIZE) return response(false);
        if(StoragePath(c.args[0]) && !LocalShell::ProtectFile(c.args[0],true)) return response(false);
        return ElevatorCommandResponse(LocalShell::ReadBytes(c.args[0]));
      }
      case ElevatorCommandType::WRITE_ATOMIC: return response(LocalShell::WriteBytesAtomic(c.args[0], c.dataBytes));
      case ElevatorCommandType::CREATE_FILE: return response(c.args[1]=="true" ? LocalShell::CreateDir(c.args[0]) && LocalShell::ProtectFile(c.args[0],true) : LocalShell::WriteBytesAtomic(c.args[0],{}));
      case ElevatorCommandType::REMOVE: return response(LocalShell::Remove(c.args[0]));
      case ElevatorCommandType::PROTECT_FILE: return response(LocalShell::ProtectFile(c.args[0],true));
      default: return response(false);
    }
  } catch(...) { return response(false); }
}
#endif
