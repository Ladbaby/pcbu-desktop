#include "LocalShell.h"
#include <mutex>

#include <boost/filesystem.hpp>
#ifdef WINDOWS
#include <boost/process/v1.hpp>
#else
#include <boost/asio.hpp>
#include <boost/process/v2/environment.hpp>
#include <boost/process/v2/process.hpp>
#include <boost/process/v2/stdio.hpp>
#endif
#include <algorithm>
#include <cstring>
#include <fstream>
#ifndef WINDOWS
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#endif
#include <spdlog/spdlog.h>

#include "utils/StringUtils.h"

#ifdef WINDOWS
#include <Windows.h>
#include <aclapi.h>
#include <boost/process/v1/windows.hpp>
// #include <boost/process/v2/windows/creation_flags.hpp>
#include <sddl.h>
#ifndef NOMINMAX
#undef min
#undef max
#endif
#undef CreateFile

#define SHELL_NAME "cmd.exe"
#define SHELL_CMD_ARG "/c"
#elif LINUX
#define SHELL_NAME "bash"
#define SHELL_CMD_ARG "-c"
#define CHOWN_USER "root:root"
#elif APPLE
#define SHELL_NAME "zsh"
#define SHELL_CMD_ARG "-c"
#define SHELL_NO_RC_ARG "-f"
#define CHOWN_USER "root"
#endif

namespace { thread_local std::string operationError; }
void LocalShell::ClearOperationError() { operationError.clear(); }
bool LocalShell::FailOperation(const char *stage, unsigned long code) {
  operationError = fmt::format("Stage={}, Code={}", stage, code);
  return false;
}
std::string LocalShell::GetOperationError() { return operationError; }

bool LocalShell::IsRunningAsAdmin() {
#ifdef WINDOWS
  BOOL isAdmin = FALSE;
  PSID adminGroup = nullptr;
  SID_IDENTIFIER_AUTHORITY ntAuthority = SECURITY_NT_AUTHORITY;
  if(!AllocateAndInitializeSid(&ntAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &adminGroup)) {
    spdlog::error("AllocateAndInitializeSid failed. (Code={})", GetLastError());
    return false;
  }
  if(!CheckTokenMembership(nullptr, adminGroup, &isAdmin)) {
    spdlog::error("CheckTokenMembership failed. (Code={})", GetLastError());
    isAdmin = FALSE;
  }
  if(adminGroup)
    FreeSid(adminGroup);
  return isAdmin;
#else
  return geteuid() == 0;
#endif
}

ShellCmdResult LocalShell::RunCommand(const std::string &cmd) {
  return RunShell(cmd, false);
}

ShellCmdResult LocalShell::RunUserCommand(const std::string &cmd) {
  return RunShell(cmd, true);
}

ShellCmdResult LocalShell::RunShell(const std::string &cmd, bool loadUserConfig) {
#ifdef WINDOWS
  boost::process::v1::ipstream outStream{};
  boost::process::v1::ipstream errStream{};
  boost::process::v1::child proc(fmt::format("{0} {1} \"{2}\"", SHELL_NAME, SHELL_CMD_ARG, cmd), boost::process::v1::std_out > outStream,
                                 boost::process::v1::std_err > errStream, boost::process::v1::windows::create_no_window);
  std::string output{};
  std::string line{};
  while(outStream && std::getline(outStream, line) && !line.empty())
    output.append(line + "\n");
  while(errStream && std::getline(errStream, line) && !line.empty())
    output.append(line + "\n");
  proc.wait();
#else
  std::vector<std::string> args{SHELL_CMD_ARG, cmd};
#ifdef SHELL_NO_RC_ARG
  if(!loadUserConfig)
    args.insert(args.begin(), SHELL_NO_RC_ARG);
#endif
  boost::asio::io_context ctx{};
  boost::asio::readable_pipe pipe{ctx};
  boost::process::v2::process proc(ctx, boost::process::v2::environment::find_executable(SHELL_NAME), args,
                                   boost::process::v2::process_stdio{nullptr, pipe, pipe});

  std::string output{};
  boost::system::error_code ec;
  boost::asio::read(pipe, boost::asio::dynamic_buffer(output), ec);
  proc.wait();
#endif

  spdlog::debug("Process exit. Code: {}", proc.exit_code());
  auto result = ShellCmdResult();
  result.exitCode = proc.exit_code();
  result.output = output;
  return result;
}

void LocalShell::SpawnCommand(const std::string &cmd) {
#ifdef WINDOWS
  boost::process::v1::child proc(fmt::format("{0} {1} \"{2}\"", SHELL_NAME, SHELL_CMD_ARG, cmd), boost::process::v1::windows::create_no_window);
  proc.detach();
#else
  boost::asio::io_context ctx{};
  boost::process::v2::process proc(ctx, boost::process::v2::environment::find_executable(SHELL_NAME), {SHELL_CMD_ARG, cmd});
  proc.detach();
#endif
}

bool LocalShell::CreateDir(const std::filesystem::path &path) {
#ifdef WINDOWS
  if(!IsRunningAsAdmin()) {
    boost::system::error_code ec{};
    boost::filesystem::create_directories(boost::filesystem::path(path), ec);
    return !ec.failed();
  }
  LocalShell::StoragePathGuard rootGuard(path);
  if(!rootGuard.IsValid()) return FailOperation("directory.ancestry", ERROR_REPARSE_TAG_INVALID);
  // Never recreate an unreadable existing directory.
  if(std::filesystem::exists(path))
    return std::filesystem::is_directory(path) && ProtectFile(path, true);
  if(!std::filesystem::exists(path.parent_path()) && !CreateDir(path.parent_path()))
    return false;
  PSECURITY_DESCRIPTOR descriptor{};
  if(!ConvertStringSecurityDescriptorToSecurityDescriptorW(
         L"O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)", SDDL_REVISION_1, &descriptor, nullptr))
    return false;
  SECURITY_ATTRIBUTES attributes{sizeof(SECURITY_ATTRIBUTES), descriptor, FALSE};
  const bool created = CreateDirectoryW(path.c_str(), &attributes) != FALSE;
  const auto error = created ? ERROR_SUCCESS : GetLastError();
  LocalFree(descriptor);
  if(!created && error != ERROR_ALREADY_EXISTS) return FailOperation("directory.create", error);
  return std::filesystem::is_directory(path) && ProtectFile(path, true);
#else
  boost::system::error_code ec{};
  boost::filesystem::create_directories(boost::filesystem::path(path), ec);
  return !ec.failed();
#endif
}

bool LocalShell::CreateFile(const std::filesystem::path &path) {
  std::ofstream file(path);
  return file.is_open();
}

bool LocalShell::Remove(const std::filesystem::path &path, bool recursive) {
  boost::system::error_code ec{};
  if(recursive)
    boost::filesystem::remove_all(boost::filesystem::path(path), ec);
  else
    boost::filesystem::remove(boost::filesystem::path(path), ec);
  return !ec.failed();
}

std::vector<uint8_t> LocalShell::ReadBytes(const std::filesystem::path &path) {
  std::ifstream file{};
  file.open(path, std::ios_base::binary);
  if(!file) {
    spdlog::error("Failed to open file '{}'.", path.string());
    return {};
  }
  return {std::istreambuf_iterator<char>(file), std::istreambuf_iterator<char>()};
}

bool LocalShell::WriteBytes(const std::filesystem::path &path, const std::vector<uint8_t> &data) {
  std::ofstream file(path, std::ios::out | std::ios::binary);
  file.write(reinterpret_cast<const char *>(data.data()), (std::streamsize)data.size());
  file.close();
  return !file.fail() && !file.bad();
}

#ifdef WINDOWS
namespace {
std::mutex storagePrivilegeMutex;
class ScopedStoragePrivileges {
  std::unique_lock<std::mutex> lock{storagePrivilegeMutex};
  HANDLE token{};
  TOKEN_PRIVILEGES oldBackup{}, oldRestore{};
  bool backupChanged{}, restoreChanged{};
  void Enable(const wchar_t *name, TOKEN_PRIVILEGES &previous, bool &changed) {
    TOKEN_PRIVILEGES privileges{};
    privileges.PrivilegeCount = 1;
    if(!LookupPrivilegeValueW(nullptr, name, &privileges.Privileges[0].Luid))
      return;
    privileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    DWORD size = sizeof(previous);
    changed = AdjustTokenPrivileges(token, FALSE, &privileges, sizeof(previous), &previous, &size) && GetLastError() == ERROR_SUCCESS;
  }
public:
  ScopedStoragePrivileges() {
    if(OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token)) {
      Enable(L"SeBackupPrivilege", oldBackup, backupChanged);
      Enable(L"SeRestorePrivilege", oldRestore, restoreChanged);
    }
  }
  ~ScopedStoragePrivileges() {
    if(token) {
      if(restoreChanged) AdjustTokenPrivileges(token, FALSE, &oldRestore, 0, nullptr, nullptr);
      if(backupChanged) AdjustTokenPrivileges(token, FALSE, &oldBackup, 0, nullptr, nullptr);
      CloseHandle(token);
    }
  }
};
struct StorageSecurity {
  PSECURITY_DESCRIPTOR descriptor{};
  SECURITY_ATTRIBUTES attributes{sizeof(SECURITY_ATTRIBUTES), nullptr, FALSE};
  StorageSecurity() {
    if(ConvertStringSecurityDescriptorToSecurityDescriptorW(
           L"O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)", SDDL_REVISION_1, &descriptor, nullptr))
      attributes.lpSecurityDescriptor = descriptor;
  }
  ~StorageSecurity() { if(descriptor) LocalFree(descriptor); }
};
}
LocalShell::StoragePathGuard::StoragePathGuard(const std::filesystem::path &path) {
  const auto absolute = std::filesystem::absolute(path).lexically_normal();
  if(absolute.empty() || !absolute.is_absolute()) return;
  std::vector<std::filesystem::path> components;
  for(auto current = absolute; !current.empty();) {
    components.push_back(current);
    if(current == current.root_path()) break;
    current = current.parent_path();
  }
  std::reverse(components.begin(), components.end());
  for(size_t i = 0; i < components.size(); ++i) {
    const bool leaf = i + 1 == components.size();
    HANDLE handle = CreateFileW(components[i].c_str(), FILE_READ_ATTRIBUTES,
                                FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING,
                                FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
    if(handle == INVALID_HANDLE_VALUE) {
      const auto error = GetLastError();
      if(error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND) {
        // The deepest existing ancestor remains pinned; the requested descendant
        // cannot be opened yet. Creation/protection must acquire a fresh guard.
        valid = !handles.empty();
        return;
      }
      return;
    }
    BY_HANDLE_FILE_INFORMATION info{};
    if(!GetFileInformationByHandle(handle, &info) || (info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) ||
       (!leaf && !(info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) ||
       ((info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) == 0 && info.nNumberOfLinks != 1)) {
      CloseHandle(handle);
      return;
    }
    handles.push_back(handle);
  }
  valid = !handles.empty();
}
LocalShell::StoragePathGuard::~StoragePathGuard() { for(auto handle : handles) CloseHandle(handle); }
#endif

bool LocalShell::ProtectFile(const std::filesystem::path &path, bool enabled) {
#ifdef WINDOWS
  LocalShell::StoragePathGuard guard(path);
  if(!guard.IsValid())
    return FailOperation("acl.ancestry", ERROR_REPARSE_TAG_INVALID);
  ScopedStoragePrivileges privileges;
  HANDLE handle = CreateFileW(path.c_str(), READ_CONTROL | WRITE_DAC | WRITE_OWNER,
                              FILE_SHARE_READ, nullptr, OPEN_EXISTING,
                              FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
  if(handle == INVALID_HANDLE_VALUE)
    return FailOperation("acl.open", GetLastError());
  BY_HANDLE_FILE_INFORMATION info{};
  if(!GetFileInformationByHandle(handle, &info) ||
     (info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) ||
     (!(info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) && info.nNumberOfLinks != 1)) {
    CloseHandle(handle);
    return false;
  }
  StorageSecurity security;
  bool success = false;
  if(security.descriptor) {
    PACL dacl{};
    PSID owner{};
    BOOL present{}, defaulted{};
    if(GetSecurityDescriptorDacl(security.descriptor, &present, &dacl, &defaulted) &&
       GetSecurityDescriptorOwner(security.descriptor, &owner, &defaulted)) {
      const auto setResult = SetSecurityInfo(handle, SE_FILE_OBJECT,
                               DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION | OWNER_SECURITY_INFORMATION,
                               owner, nullptr, dacl, nullptr);
      success = setResult == ERROR_SUCCESS;
      if(!success) FailOperation("acl.set", setResult);
      if(success) {
        PACL actual{};
        PSID actualOwner{};
        PSECURITY_DESCRIPTOR actualDescriptor{};
        const auto getResult = GetSecurityInfo(handle, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION | OWNER_SECURITY_INFORMATION,
                                  &actualOwner, nullptr, &actual, nullptr, &actualDescriptor);
        success = getResult == ERROR_SUCCESS;
        if(!success) FailOperation("acl.readback", getResult);
        if(success) {
          SECURITY_DESCRIPTOR_CONTROL control{};
          DWORD revision{};
          success = actual && actualOwner && EqualSid(owner, actualOwner) && actual->AceCount == 2 &&
                    GetSecurityDescriptorControl(actualDescriptor, &control, &revision) && (control & SE_DACL_PROTECTED);
          bool system = false, administrators = false;
          for(DWORD i = 0; success && i < actual->AceCount; ++i) {
            void *entry{};
            success = GetAce(actual, i, &entry) != FALSE;
            if(!success) break;
            const auto ace = static_cast<ACCESS_ALLOWED_ACE *>(entry);
            success = ace->Header.AceType == ACCESS_ALLOWED_ACE_TYPE && ace->Mask == FILE_ALL_ACCESS;
            auto sid = reinterpret_cast<PSID>(&ace->SidStart);
            if(IsWellKnownSid(sid, WinLocalSystemSid)) system = true;
            else if(IsWellKnownSid(sid, WinBuiltinAdministratorsSid)) administrators = true;
            else success = false;
          }
          success = success && system && administrators;
        }
        if(actualDescriptor) LocalFree(actualDescriptor);
      }
    }
  }
  CloseHandle(handle);
  if(!success && GetOperationError().empty()) FailOperation("acl.verify", ERROR_INVALID_SECURITY_DESCR);
  return success;
#else
  if(!enabled)
    return true;
  struct stat info{};
  if(lstat(path.c_str(), &info) != 0 || S_ISLNK(info.st_mode))
    return false;
  return chown(path.c_str(), 0, 0) == 0 && chmod(path.c_str(), S_ISDIR(info.st_mode) ? 0755 : 0600) == 0;
#endif
}

bool LocalShell::WriteBytesAtomic(const std::filesystem::path &path, const std::vector<uint8_t> &data) {
  const auto parent = path.parent_path();
  if(!ProtectFile(parent, true))
    return false;
  const auto random = StringUtils::RandomString(24, false);
  if(random.empty())
    return false;
  const auto temporary = parent / (".pcbu-" + random + ".tmp");
#ifdef WINDOWS
  LocalShell::StoragePathGuard guard(parent);
  if(!guard.IsValid())
    return FailOperation("atomic.ancestry", ERROR_REPARSE_TAG_INVALID);
  if(std::filesystem::exists(path) && !ProtectFile(path, true))
    return false;
  StorageSecurity security;
  if(!security.descriptor)
    return false;
  HANDLE file = CreateFileW(temporary.c_str(), GENERIC_WRITE, 0, &security.attributes, CREATE_NEW,
                            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_WRITE_THROUGH | FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
  if(file == INVALID_HANDLE_VALUE)
    return FailOperation("atomic.create", GetLastError());
  size_t offset = 0;
  bool success = true;
  while(offset < data.size()) {
    DWORD written{};
    const DWORD length = static_cast<DWORD>(std::min<size_t>(data.size() - offset, 1024 * 1024));
    if(!WriteFile(file, data.data() + offset, length, &written, nullptr)) {
      FailOperation("atomic.write", GetLastError());
      success = false;
      break;
    }
    if(written == 0) {
      FailOperation("atomic.short_write", ERROR_WRITE_FAULT);
      success = false;
      break;
    }
    offset += written;
  }
  if(success && !FlushFileBuffers(file)) success = FailOperation("atomic.flush", GetLastError());
  CloseHandle(file);
  success = success && ProtectFile(temporary, true);
  if(success && !MoveFileExW(temporary.c_str(), path.c_str(), MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH))
    success = FailOperation("atomic.replace", GetLastError());
  if(!success)
    DeleteFileW(temporary.c_str());
  return success;
#else
  const int file = open(temporary.c_str(), O_CREAT | O_EXCL | O_WRONLY | O_NOFOLLOW, 0600);
  if(file < 0)
    return false;
  size_t offset = 0;
  bool success = true;
  while(offset < data.size()) {
    const auto written = write(file, data.data() + offset, data.size() - offset);
    if(written <= 0) { success = false; break; }
    offset += static_cast<size_t>(written);
  }
  success = success && fchmod(file, 0600) == 0 && fchown(file, 0, 0) == 0 && fsync(file) == 0;
  close(file);
  if(success)
    success = rename(temporary.c_str(), path.c_str()) == 0;
  if(!success)
    unlink(temporary.c_str());
  return success;
#endif
}
