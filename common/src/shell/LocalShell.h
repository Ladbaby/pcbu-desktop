#ifndef LOCALSHELL_H
#define LOCALSHELL_H

#include <filesystem>
#ifdef WINDOWS
#include <vector>
#endif

#include "ElevatorCommands.h"

#ifdef WINDOWS
#undef CreateFile
#endif

class LocalShell {
public:
#ifdef WINDOWS
  // Pins existing directory ancestors (without delete sharing) for the lifetime of a storage operation.
  class StoragePathGuard {
    std::vector<void *> handles;
    bool valid{};
  public:
    explicit StoragePathGuard(const std::filesystem::path &path);
    ~StoragePathGuard();
    StoragePathGuard(const StoragePathGuard &) = delete;
    StoragePathGuard &operator=(const StoragePathGuard &) = delete;
    bool IsValid() const { return valid; }
  };
#endif
  static bool IsRunningAsAdmin();

  static ShellCmdResult RunCommand(const std::string &cmd);
  static ShellCmdResult RunUserCommand(const std::string &cmd);
  static void SpawnCommand(const std::string &cmd);

  static bool CreateDir(const std::filesystem::path &path);
  static bool CreateFile(const std::filesystem::path &path);
  static bool Remove(const std::filesystem::path &path, bool recursive = false);

  static std::vector<uint8_t> ReadBytes(const std::filesystem::path &path);
  static bool WriteBytes(const std::filesystem::path &path, const std::vector<uint8_t> &data);
  static bool WriteBytesAtomic(const std::filesystem::path &path, const std::vector<uint8_t> &data);

  static bool ProtectFile(const std::filesystem::path &path, bool enabled);
  // Thread-local, bounded stage/code only; never contains file contents or paths.
  static void ClearOperationError();
  static bool FailOperation(const char *stage, unsigned long code);
  static std::string GetOperationError();

private:
  LocalShell() = default;

  static ShellCmdResult RunShell(const std::string &cmd, bool loadUserConfig);

};

#endif
