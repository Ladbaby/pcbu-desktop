#include "WinFirewallHelper.h"
#include <Windows.h>
#include <netfw.h>
#include <filesystem>
#include "storage/AppSettings.h"
#include "shell/LocalShell.h"

namespace {
struct Bstr {
  BSTR value;
  explicit Bstr(const wchar_t *s):value(SysAllocString(s)){}
  ~Bstr(){SysFreeString(value);}
  operator BSTR() const {return value;}
};
bool Apply(bool install) {
  const HRESULT init = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
  if(FAILED(init) && init != RPC_E_CHANGED_MODE)
    return LocalShell::FailOperation("firewall.com_init", static_cast<unsigned long>(init));
  INetFwPolicy2 *policy{};
  INetFwRules *rules{};
  bool ok = SUCCEEDED(CoCreateInstance(__uuidof(NetFwPolicy2),nullptr,CLSCTX_INPROC_SERVER,__uuidof(INetFwPolicy2),reinterpret_cast<void **>(&policy)));
  if(ok) ok=SUCCEEDED(policy->get_Rules(&rules));
  const wchar_t *names[]={L"PulseUnlock Fork Local TCP",L"PulseUnlock Fork Local UDP",L"PulseUnlock Provider Local TCP",L"PulseUnlock Provider Local UDP"};
  if(ok) {
    // Delete only exact application-owned names, never all rules for a program.
    for(auto name : {L"PulseUnlock", L"PC Bio Unlock", L"LogonUI (PulseUnlock)", L"LogonUI (PC Bio Unlock)"}) {
      auto hr=rules->Remove(Bstr(name));
      if(FAILED(hr) && hr!=HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND)) ok=false;
    }
    for(auto name:names) {
      auto hr=rules->Remove(Bstr(name));
      if(FAILED(hr) && hr!=HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND)) ok=false;
    }
  }
  if(ok && install) {
    const auto settings=AppSettings::Get();
    if(!settings.pairingServerPort || !settings.unlockServerPort || !settings.pairingDiscoveryPort) ok=false;
    wchar_t exe[MAX_PATH]{}, system[MAX_PATH]{};
    if(!GetModuleFileNameW(nullptr,exe,MAX_PATH) || !GetSystemDirectoryW(system,MAX_PATH)) ok=false;
    auto desktop=std::filesystem::path(exe).parent_path()/"pcbu_desktop.exe";
    auto logon=std::filesystem::path(system)/"LogonUI.exe";
    for(int i=0;ok && i<4;++i) {
      const bool udp=(i%2)==1;
      if(udp && !settings.udpDiscoveryEnabled) continue;
      INetFwRule *rule{};
      ok=SUCCEEDED(CoCreateInstance(__uuidof(NetFwRule),nullptr,CLSCTX_INPROC_SERVER,__uuidof(INetFwRule),reinterpret_cast<void **>(&rule)));
      if(!ok) break;
      auto ports=udp ? std::to_wstring(settings.pairingDiscoveryPort) :
        std::to_wstring(settings.pairingServerPort)+L","+std::to_wstring(settings.unlockServerPort);
      auto program=(i<2?desktop:logon).wstring();
      ok=SUCCEEDED(rule->put_Name(Bstr(names[i]))) &&
         SUCCEEDED(rule->put_ApplicationName(Bstr(program.c_str()))) &&
         SUCCEEDED(rule->put_Protocol(udp?NET_FW_IP_PROTOCOL_UDP:NET_FW_IP_PROTOCOL_TCP)) &&
         SUCCEEDED(rule->put_LocalPorts(Bstr(ports.c_str()))) &&
         SUCCEEDED(rule->put_RemoteAddresses(Bstr(L"LocalSubnet"))) &&
         SUCCEEDED(rule->put_Profiles(NET_FW_PROFILE2_PRIVATE)) &&
         SUCCEEDED(rule->put_Direction(NET_FW_RULE_DIR_IN)) &&
         SUCCEEDED(rule->put_Action(NET_FW_ACTION_ALLOW)) &&
         SUCCEEDED(rule->put_EdgeTraversal(VARIANT_FALSE)) &&
         SUCCEEDED(rule->put_Enabled(VARIANT_TRUE)) && SUCCEEDED(rules->Add(rule));
      rule->Release();
    }
  }
  if(rules) rules->Release();
  if(policy) policy->Release();
  if(SUCCEEDED(init)) CoUninitialize();
  if(!ok && LocalShell::GetOperationError().empty())
    LocalShell::FailOperation(install ? "firewall.configure" : "firewall.remove", ERROR_GEN_FAILURE);
  return ok;
}
}
bool WinFirewallHelper::ConfigureOwnedRules(){return Apply(true);}
bool WinFirewallHelper::RemoveOwnedRules(){return Apply(false);}
