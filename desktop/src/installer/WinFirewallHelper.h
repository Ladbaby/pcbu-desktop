#pragma once
class WinFirewallHelper {
public:
  static bool ConfigureOwnedRules();
  static bool RemoveOwnedRules();
};
