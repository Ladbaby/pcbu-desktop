#include "PairedDevicesStorage.h"

#include <algorithm>
#include <nlohmann/json.hpp>
#include <spdlog/spdlog.h>
#include <stdexcept>
#include <utility>

#include "AppSettings.h"
#include "shell/Shell.h"
#include "utils/StringUtils.h"

std::vector<PairedDevice> PairedDevicesStorage::g_Cache{};
std::mutex PairedDevicesStorage::g_Mutex{};
bool PairedDevicesStorage::g_Loaded = false;
size_t PairedDevicesStorage::g_RemovedCloudCount = 0;

namespace {
nlohmann::json SerializeDevices(const std::vector<PairedDevice> &devices) {
  auto result = nlohmann::json::array();
  for(const auto &device : devices) {
    auto servers = nlohmann::json::array();
    for(const auto &server : device.sshServers)
      servers.push_back({{"host", server.host}, {"user", server.user}, {"keyPath", server.keyPath}, {"passwordEnc", server.passwordEnc}});
    result.push_back({{"id", device.id}, {"pairingMethod", PairingMethodUtils::ToString(device.pairingMethod)},
                     {"deviceName", device.deviceName}, {"userName", device.userName}, {"passwordEnc", device.passwordEnc},
                     {"encryptionKey", device.encryptionKey}, {"ipAddress", device.ipAddress}, {"tcpPort", device.tcpPort},
                     {"udpPort", device.udpPort}, {"udpManualPort", device.udpManualPort},
                     {"bluetoothAddress", device.bluetoothAddress}, {"sshServers", servers}});
  }
  return result;
}
void EnsureStorageDirectory(const std::filesystem::path &directory) {
#ifdef WINDOWS
  if(!Shell::CreateDir(directory))
#else
  if(!std::filesystem::exists(directory) && !Shell::CreateDir(directory))
#endif
    throw std::runtime_error("Cannot create paired-device storage directory.");
  if(!Shell::ProtectFile(directory, true))
    throw std::runtime_error("Cannot secure paired-device storage directory.");
}
}

std::optional<PairedDevice> PairedDevicesStorage::GetDeviceByID(const std::string &id) {
  for(const auto &device : GetDevices())
    if(device.id == id)
      return device;
  return {};
}

std::vector<PairedDevice> PairedDevicesStorage::GetDevicesForUser(const std::string &userName) {
  std::vector<PairedDevice> result{};
#ifdef WINDOWS
  const auto userNameLower = StringUtils::ToLower(userName);
  std::string principalName;
  const auto userSplit = StringUtils::Split(userName, "\\");
  if(userSplit.size() == 2 && userSplit[1].find('@') != std::string::npos)
    principalName = StringUtils::ToLower(userSplit[1]);
#endif
  for(const auto &device : GetDevices()) {
#ifdef WINDOWS
    const auto deviceUserName = StringUtils::ToLower(device.userName);
    if(deviceUserName == userNameLower || (!principalName.empty() && deviceUserName == principalName))
#else
    if(device.userName == userName)
#endif
      result.emplace_back(device);
  }
  return result;
}

bool PairedDevicesStorage::AddDevice(const PairedDevice &device) {
  auto devices = GetDevices();
  std::erase_if(devices, [&](const PairedDevice &d) { return d.id == device.id; });
  devices.emplace_back(device);
  return SaveDevices(devices);
}

void PairedDevicesStorage::RemoveDevice(const std::string &id) {
  auto devices = GetDevices();
  std::erase_if(devices, [&](const PairedDevice &d) { return d.id == id; });
  if(!SaveDevices(devices))
    throw std::runtime_error("Cannot persist paired-device removal.");
}

std::vector<PairedDevice> PairedDevicesStorage::GetDevices() {
  std::unique_lock lock(g_Mutex);
  if(!g_Loaded) {
    g_Cache = Load();
    g_Loaded = true;
  }
  return g_Cache;
}

std::vector<PairedDevice> PairedDevicesStorage::Load() {
  const auto directory = AppSettings::GetBaseDir();
  EnsureStorageDirectory(directory);
  const auto path = directory / DEVICES_FILE_NAME;
  const bool exists = Shell::Exists(path);
  if(!exists)
    return {};
  if(!Shell::ProtectFile(path, true))
    throw std::runtime_error("Cannot secure paired-device storage.");
  auto bytes = Shell::ReadBytes(path);
  if(bytes.empty())
    throw std::runtime_error("Paired-device storage is empty or unreadable; refusing to replace it.");
  try {
    auto json = nlohmann::json::parse(bytes);
    // Historical empty storage was written as null.
    if(json.is_null())
      json = nlohmann::json::array();
    if(!json.is_array())
      throw std::runtime_error("Invalid storage root.");
    std::vector<PairedDevice> devices;
    size_t removed = 0;
    bool needsMigration = false;
    for(const auto &entry : json) {
      if(entry.at("pairingMethod").get<std::string>() == "CLOUD") {
        ++removed;
        needsMigration = true;
        continue;
      }
      needsMigration = needsMigration || entry.contains("cloudToken");
      PairedDevice device;
      device.id = entry.at("id");
      device.pairingMethod = PairingMethodUtils::FromString(entry.at("pairingMethod"));
      device.deviceName = entry.at("deviceName");
      device.userName = entry.at("userName");
      device.passwordEnc = entry.at("passwordEnc");
      device.encryptionKey = entry.at("encryptionKey");
      device.ipAddress = entry.at("ipAddress");
      device.bluetoothAddress = entry.at("bluetoothAddress");
      const auto checkedPort = [&](const char *name) {
        const auto &value = entry.at(name);
        if(!value.is_number_integer())
          throw std::runtime_error("Invalid stored port.");
        const auto port = value.get<int64_t>();
        if(port < 0 || port > 65535)
          throw std::runtime_error("Invalid stored port.");
        return static_cast<uint16_t>(port);
      };
      device.tcpPort = checkedPort("tcpPort");
      device.udpPort = checkedPort("udpPort");
      device.udpManualPort = checkedPort("udpManualPort");
      if(entry.contains("sshServers")) {
        if(!entry.at("sshServers").is_array())
          throw std::runtime_error("Invalid stored SSH server list.");
        for(const auto &serverEntry : entry.at("sshServers")) {
          SshServer server;
          server.host = serverEntry.value("host", "");
          server.user = serverEntry.value("user", "");
          server.keyPath = serverEntry.value("keyPath", "");
          server.passwordEnc = serverEntry.value("passwordEnc", "");
          device.sshServers.emplace_back(std::move(server));
        }
      }
      devices.emplace_back(std::move(device));
    }
    if(needsMigration) {
      const auto data = SerializeDevices(devices).dump();
      if(!Shell::WriteBytesAtomic(path, {data.begin(), data.end()}))
        throw std::runtime_error("Cannot migrate paired-device storage.");
      g_RemovedCloudCount += removed;
    }
    return devices;
  } catch(...) {
    // Do not disclose parser input, and do not turn a failed load into valid-empty storage.
    throw std::runtime_error("Cannot load or migrate paired-device storage; original records have not been replaced.");
  }
}

bool PairedDevicesStorage::SaveDevices(const std::vector<PairedDevice> &devices) {
  std::unique_lock lock(g_Mutex);
  try {
    // Never allow a failed initial load to be silently overwritten.
    if(!g_Loaded) {
      g_Cache = Load();
      g_Loaded = true;
    }
    const auto directory = AppSettings::GetBaseDir();
    EnsureStorageDirectory(directory);
    const auto data = SerializeDevices(devices).dump();
    if(!Shell::WriteBytesAtomic(directory / DEVICES_FILE_NAME, {data.begin(), data.end()}))
      throw std::runtime_error("Cannot persist paired-device storage.");
    g_Cache = devices;
    return true;
  } catch(...) {
    spdlog::error("Failed to save paired-device storage.");
    return false;
  }
}

size_t PairedDevicesStorage::ConsumeRemovedCloudCount() {
  std::unique_lock lock(g_Mutex);
  return std::exchange(g_RemovedCloudCount, 0);
}

void PairedDevicesStorage::InvalidateCache() {
  std::unique_lock lock(g_Mutex);
  g_Cache.clear();
  g_Loaded = false;
}
