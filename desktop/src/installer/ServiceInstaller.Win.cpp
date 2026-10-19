#include "ServiceInstaller.h"

#include <Windows.h>

#include <ShlObj.h>

#include "WinFirewallHelper.h"
#include "platform/PlatformHelper.h"
#include "shell/Shell.h"
#include "storage/AppSettings.h"
#include "storage/PairedDevicesStorage.h"
#include "utils/ResourceHelper.h"
#include "utils/StringUtils.h"

#define LIB_MODULE_FILE "win_pulseunlock.dll"
#define LIB_MODULE_FILE_OLD "win-pcbiounlock.dll"
#define CRED_PROVIDER_NAME "win_pulseunlock"
#define CRED_PROVIDER_GUID "{74A23DE2-B81D-46EC-E129-CD32507ED716}"
#define APP_FIREWALL_RULE_NAME "PulseUnlock"
#define APP_FIREWALL_RULE_NAME_OLD "PC Bio Unlock"
#define LOGONUI_FIREWALL_RULE_NAME "LogonUI (PulseUnlock)"
#define LOGONUI_FIREWALL_RULE_NAME_OLD "LogonUI (PC Bio Unlock)"

std::filesystem::path ServiceInstaller_GetSysDir() {
  wchar_t sysDir[MAX_PATH]{};
  if(GetSystemDirectoryW(sysDir, MAX_PATH) > 0)
    return sysDir;
  return "C:\\Windows\\System32";
}

ServiceInstaller::ServiceInstaller(const std::function<void(const std::string &)> &logCallback) {
  m_Logger = logCallback;
}

std::vector<ServiceSetting> ServiceInstaller::GetSettings() {
  return {
      {"unlockBehavior",
       I18n::Get("service_setting_unlock_behavior"),
       {
           {"foreground_lock_only", I18n::Get("unlock_behavior_foreground_lock_only")},
           {"foreground_always", I18n::Get("unlock_behavior_foreground_always")},
           {"key_press_lock_only", I18n::Get("unlock_behavior_key_press_lock_only")},
           {"key_press", I18n::Get("unlock_behavior_key_press")},
           {"none", I18n::Get("unlock_behavior_none")},
       },
       AppSettings::Get().unlockBehavior,
       "key_press_lock_only"},
      {"hidePasswordField", I18n::Get("service_setting_hide_pw_field"), AppSettings::Get().winHidePasswordField, false},
      {"forceCredProv", I18n::Get("service_setting_force_cred_prov"), AppSettings::Get().winForceDefaultCredProv, true},
  };
}

void ServiceInstaller::ApplySettings(const std::vector<ServiceSetting> &settings, bool useDefault) {
  for(auto setting : settings) {
    if(setting.id == "unlockBehavior") {
      auto storage = AppSettings::Get();
      storage.unlockBehavior = useDefault ? setting.defaultValue : setting.selectedValue;
      AppSettings::Save(storage);
    } else if(setting.id == "hidePasswordField") {
      auto storage = AppSettings::Get();
      storage.winHidePasswordField = useDefault ? setting.defaultVal : setting.enabled;
      AppSettings::Save(storage);
    } else if(setting.id == "forceCredProv") {
      auto storage = AppSettings::Get();
      storage.winForceDefaultCredProv = useDefault ? setting.defaultVal : setting.enabled;
      AppSettings::Save(storage);
    } else {
      spdlog::warn("Unknown service setting {}.", setting.id);
    }
  }
}

bool ServiceInstaller::IsInstalled() {
  auto sysDir = ServiceInstaller_GetSysDir();
  return std::filesystem::exists(sysDir / LIB_MODULE_FILE) || std::filesystem::exists(sysDir / LIB_MODULE_FILE_OLD);
}

void ServiceInstaller::Install() {
  m_Logger("Installing embedded credential provider...");
  if(!Shell::WindowsOperation(ElevatorCommandType::INSTALL_PROVIDER))
    throw std::runtime_error("Cannot install credential provider.");
  if(!Shell::WindowsOperation(ElevatorCommandType::CONFIGURE_FIREWALL))
    throw std::runtime_error("Cannot configure local-only firewall rules.");

  m_Logger("Setting default credential provider...");
  for(auto device : PairedDevicesStorage::GetDevices()) {
    if(!PlatformHelper::SetDefaultCredProv(device.userName, CRED_PROVIDER_GUID))
      m_Logger(fmt::format("Failed setting default credential provider for user '{}'.", device.userName));
  }
  m_Logger("Provider and firewall stages completed; settings still need to be saved.");
}

void ServiceInstaller::Uninstall(bool /*fullUninstall*/) {
  if(!Shell::WindowsOperation(ElevatorCommandType::REMOVE_PROVIDER))
    throw std::runtime_error("Cannot remove credential provider.");
  if(!Shell::WindowsOperation(ElevatorCommandType::REMOVE_FIREWALL))
    throw std::runtime_error("Cannot remove owned firewall rules.");
  m_Logger("Provider and firewall stages completed; settings still need to be saved.");
}
