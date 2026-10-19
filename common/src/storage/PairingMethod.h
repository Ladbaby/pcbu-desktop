#ifndef PCBU_DESKTOP_PAIRINGMETHOD_H
#define PCBU_DESKTOP_PAIRINGMETHOD_H

#include <spdlog/spdlog.h>
#include <string>
#include <stdexcept>

// Value 2 is reserved for the removed cloud transport.
enum class PairingMethod : int { TCP = 0, BLUETOOTH = 1, UDP = 3, MANUAL_UDP = 4 };

class PairingMethodUtils {
public:
  static std::string ToString(PairingMethod method) {
    if(method == PairingMethod::TCP)
      return "TCP";
    else if(method == PairingMethod::BLUETOOTH)
      return "BLUETOOTH";
    else if(method == PairingMethod::UDP)
      return "UDP";
    else if(method == PairingMethod::MANUAL_UDP)
      return "MANUAL_UDP";
    spdlog::warn("Unknown pairing method.");
    return {};
  }

  static PairingMethod FromString(const std::string &methodStr) {
    if(methodStr == "TCP")
      return PairingMethod::TCP;
    else if(methodStr == "BLUETOOTH")
      return PairingMethod::BLUETOOTH;
    else if(methodStr == "UDP")
      return PairingMethod::UDP;
    else if(methodStr == "MANUAL_UDP")
      return PairingMethod::MANUAL_UDP;
    throw std::runtime_error("Invalid pairing method.");
  }

private:
  PairingMethodUtils() = default;
};

#endif // PCBU_DESKTOP_PAIRINGMETHOD_H
