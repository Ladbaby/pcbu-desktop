#include "AppSettings.h"

#include <filesystem>
#include <stdexcept>
#include <vector>

#include <nlohmann/json.hpp>
#include <spdlog/spdlog.h>

#include "platform/PlatformHelper.h"
#include "shell/Shell.h"
#include "utils/AppInfo.h"
#include "utils/StringUtils.h"

PCBUAppStorage AppSettings::g_Cache{};
std::mutex AppSettings::g_Mutex{};

std::filesystem::path AppSettings::GetBaseDir() {
  auto newDir = GetNewBaseDir();
  auto oldDir = GetOldBaseDir();
  if(Shell::Exists(newDir / SETTINGS_FILE_NAME))
    return newDir;
  if(Shell::Exists(oldDir / SETTINGS_FILE_NAME))
    return oldDir;
  return newDir;
}

std::filesystem::path AppSettings::GetBaseUserDir() {
  auto dataDir = PlatformHelper::GetUserDataDir();
  if(dataDir.empty())
    return PlatformHelper::GetTempDir();
  return dataDir / "PulseUnlock";
}

std::filesystem::path AppSettings::GetLogsDir(bool userDir) {
  auto logsDir = userDir ? PlatformHelper::GetUserLogsDir() : PlatformHelper::GetSystemLogsDir();
  if(logsDir.empty())
    return PlatformHelper::GetTempDir() / "logs";
#ifdef WINDOWS
  return logsDir / "PulseUnlock" / "logs";
#elif APPLE
  return logsDir / "PulseUnlock";
#else
  return userDir ? logsDir / "PulseUnlock" / "logs" : logsDir / "pulse-unlock";
#endif
}

PCBUAppStorage AppSettings::Get() {
  std::unique_lock lock(g_Mutex);
  if(!g_Cache.machineID.empty())
    return g_Cache;
  g_Cache = Load();
  return g_Cache;
}

PCBUAppStorage AppSettings::Load() {
  auto defaults = LoadDefaults();
  auto settingsPath = GetBaseDir() / SETTINGS_FILE_NAME;
  if(!Shell::Exists(settingsPath)) {
    Write(defaults);
    return defaults;
  }
  auto jsonData = Shell::ReadBytes(settingsPath);
  if(jsonData.empty())
    throw std::runtime_error("Settings are unreadable; refusing to replace them.");

  try {
    auto json = nlohmann::json::parse(jsonData);
    auto settings = PCBUAppStorage();
    settings.machineID = json.value("machineID", defaults.machineID);
    settings.installedVersion = json.value("installedVersion", defaults.installedVersion);
    settings.language = json.value("language", defaults.language);
    settings.serverIP = json.value("serverIP", defaults.serverIP);
    settings.serverMAC = json.value("serverMAC", defaults.serverMAC);
    const auto port = [&](const char *name, uint16_t fallback) {
      if(!json.contains(name)) return fallback;
      const auto &value = json.at(name);
      if(!value.is_number_integer()) throw std::runtime_error("Invalid port.");
      const auto number = value.get<int64_t>();
      if(number < 1 || number > 65535) throw std::runtime_error("Invalid port.");
      return static_cast<uint16_t>(number);
    };
    settings.pairingDiscoveryPort = port("pairingDiscoveryPort", defaults.pairingDiscoveryPort);
    settings.pairingServerPort = port("pairingServerPort", defaults.pairingServerPort);
    settings.unlockServerPort = port("unlockServerPort", defaults.unlockServerPort);
    settings.clientSocketTimeout = json.value("clientSocketTimeout", defaults.clientSocketTimeout);
    settings.clientConnectTimeout = json.value("clientConnectTimeout", defaults.clientConnectTimeout);
    settings.clientConnectRetries = json.value("clientConnectRetries", defaults.clientConnectRetries);

    settings.unlockBehavior = json.value("unlockBehavior", json.value("winUnlockBehavior", defaults.unlockBehavior));
    settings.winHidePasswordField = json.value("winHidePasswordField", defaults.winHidePasswordField);
    settings.winForceDefaultCredProv = json.value("winForceDefaultCredProv", defaults.winForceDefaultCredProv);
#ifdef APPLE
    settings.unixSetPasswordPAM = true;
#else
    settings.unixSetPasswordPAM = json.value("unixSetPasswordPAM", defaults.unixSetPasswordPAM);
#endif
    settings.macLoginScreen = json.value("macLoginScreen", defaults.macLoginScreen);
    settings.automaticUpdateChecks = json.value("automaticUpdateChecks", false);
    settings.udpDiscoveryEnabled = json.value("udpDiscoveryEnabled", false);
    if(!json.contains("machineID"))
      Write(settings);
    return settings;
  } catch(const std::exception &ex) {
    throw std::runtime_error("Cannot parse application settings; original file preserved.");
  }
}

PCBUAppStorage AppSettings::LoadDefaults() {
  auto def = PCBUAppStorage();
  def.machineID = StringUtils::RandomString(32);
  def.language = "auto";
  def.serverIP = "auto";
  def.pairingDiscoveryPort = 43297;
  def.pairingServerPort = 43295;
  def.unlockServerPort = 43296;
  def.clientSocketTimeout = 120;
  def.clientConnectTimeout = 5;
  def.clientConnectRetries = 2;

  def.unlockBehavior = "key_press_lock_only";
  def.winHidePasswordField = false;
  def.winForceDefaultCredProv = false;
#ifdef APPLE
  def.unixSetPasswordPAM = true;
#else
  def.unixSetPasswordPAM = false;
#endif
  def.macLoginScreen = true;
  def.automaticUpdateChecks = false;
  def.udpDiscoveryEnabled = false;
  return def;
}

void AppSettings::Save(const PCBUAppStorage &storage) {
  std::unique_lock lock(g_Mutex);
  Write(storage);
  g_Cache = storage;
}

void AppSettings::Write(const PCBUAppStorage &storage) {
  try {
    nlohmann::json json = {
        {"machineID", storage.machineID},
        {"installedVersion", storage.installedVersion},
        {"language", storage.language},
        {"serverIP", storage.serverIP},
        {"serverMAC", storage.serverMAC},
        {"pairingDiscoveryPort", storage.pairingDiscoveryPort},
        {"pairingServerPort", storage.pairingServerPort},
        {"unlockServerPort", storage.unlockServerPort},
        {"clientSocketTimeout", storage.clientSocketTimeout},
        {"clientConnectTimeout", storage.clientConnectTimeout},
        {"clientConnectRetries", storage.clientConnectRetries},

        {"unlockBehavior", storage.unlockBehavior},
        {"winHidePasswordField", storage.winHidePasswordField},
        {"winForceDefaultCredProv", storage.winForceDefaultCredProv},
        {"unixSetPasswordPAM", storage.unixSetPasswordPAM},
        {"macLoginScreen", storage.macLoginScreen},
        {"automaticUpdateChecks", storage.automaticUpdateChecks},
        {"udpDiscoveryEnabled", storage.udpDiscoveryEnabled},
    };
    auto baseDir = GetBaseDir();
    if(!Shell::CreateDir(baseDir))
      throw std::runtime_error("Cannot create settings directory.");
    auto jsonStr = json.dump();
    if(!Shell::WriteBytesAtomic(baseDir / SETTINGS_FILE_NAME, {jsonStr.begin(), jsonStr.end()}))
      throw std::runtime_error("Cannot persist settings.");
  } catch(const std::exception &ex) {
    const std::string detail = ex.what();
    // Only forward our bounded stage diagnostics, never parser input or arbitrary exceptions.
    const auto safe = detail.starts_with("Stage=") && detail.size() < 160 ? detail : "Stage=settings.save, Code=31";
    spdlog::error("Failed writing app storage: {}", safe);
    throw std::runtime_error(std::string("Cannot persist application settings. ") + safe);
  }
}

void AppSettings::InvalidateCache() {
  std::unique_lock lock(g_Mutex);
  g_Cache = {};
}

void AppSettings::SetInstalledVersion(bool isInstalled) {
  auto settings = Get();
  settings.installedVersion = isInstalled ? AppInfo::GetVersion() : "";
  Save(settings);
}

/*
 * Migration
 */

std::filesystem::path AppSettings::GetNewBaseDir() {
#ifdef WINDOWS
  auto dataDir = PlatformHelper::GetSystemDataDir();
  if(dataDir.empty())
    return "C:\\ProgramData\\PulseUnlock";
  return dataDir / "PulseUnlock";
#else
  return PlatformHelper::GetSystemDataDir() / "pulse-unlock";
#endif
}

std::filesystem::path AppSettings::GetOldBaseDir() {
#ifdef WINDOWS
  auto dataDir = PlatformHelper::GetSystemDataDir();
  if(dataDir.empty())
    return "C:\\ProgramData\\PCBioUnlock";
  return dataDir / "PCBioUnlock";
#else
  return PlatformHelper::GetSystemDataDir() / "pc-bio-unlock";
#endif
}

bool AppSettings::NeedsMigration() {
  auto newDir = GetNewBaseDir();
  auto oldDir = GetOldBaseDir();
  if(Shell::Exists(newDir / SETTINGS_FILE_NAME))
    return false;
  if(!Shell::Exists(oldDir / SETTINGS_FILE_NAME))
    return false;
  return true;
}

void AppSettings::MigrateBaseDir() {
  if(!NeedsMigration())
    return;

#ifdef WINDOWS
  if(!Shell::WindowsOperation(ElevatorCommandType::MIGRATE_STORAGE))
    throw std::runtime_error("Cannot secure legacy storage.");
  return;
#endif
  auto newDir = GetNewBaseDir();
  auto oldDir = GetOldBaseDir();
  auto oldDevicesFile = oldDir / "paired_devices.json";
  auto newDevicesFile = newDir / "paired_devices.json";
  if(Shell::Exists(newDir)) {
    auto logsDir = GetLogsDir(false);
    std::vector<std::filesystem::path> entries{};
    for(const auto &entry : std::filesystem::directory_iterator(newDir))
      entries.push_back(entry.path());
    for(const auto &entry : entries) {
      if(entry != logsDir || Shell::Exists(oldDir / entry.filename()))
        throw std::runtime_error(fmt::format("Migration target '{}' already exists.", entry.string()));
    }
    for(const auto &entry : entries)
      MovePath(entry, oldDir / entry.filename());
    if(!Shell::Remove(newDir))
      throw std::runtime_error(fmt::format("Failed removing empty migration target '{}'.", newDir.string()));
  }
  if(Shell::Exists(oldDevicesFile) && !Shell::ProtectFile(oldDevicesFile, true))
    throw std::runtime_error("Cannot secure legacy credentials.");
  try {
    MovePath(oldDir, newDir);
  } catch(...) {
    Shell::ProtectFile(oldDevicesFile, true);
    throw;
  }
  if(Shell::Exists(newDevicesFile) && !Shell::ProtectFile(newDevicesFile, true))
    spdlog::warn("Failed setting permissions of '{}'.", newDevicesFile.string());
}

void AppSettings::MovePath(const std::filesystem::path &from, const std::filesystem::path &to) {
#ifdef WINDOWS
  auto cmd = fmt::format(R"(move "{}" "{}")", from.string(), to.string());
#else
  auto cmd = fmt::format(R"(mv "{}" "{}")", from.string(), to.string());
#endif
  auto result = Shell::RunCommand(cmd);
  if(result.exitCode != 0)
    throw std::runtime_error(fmt::format("Migration move failed. (From={}, To={}, Code={}, Output={})", from.string(), to.string(), result.exitCode,
                                         StringUtils::Trim(result.output)));
}
