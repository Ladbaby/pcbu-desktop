#ifndef ELEVATORCOMMANDS_H
#define ELEVATORCOMMANDS_H

#include <optional>
#include <string>
#include <vector>

#include <nlohmann/json.hpp>
#include <spdlog/spdlog.h>

#include "IPCHelper.h"

struct ShellCmdResult {
  int exitCode{};
  std::string output{};
};

enum class ElevatorCommandType { NONE, RUN_CMD, READ_BYTES, WRITE_BYTES, CREATE_FILE, REMOVE, PROTECT_FILE, EXISTS, WRITE_ATOMIC, INSTALL_PROVIDER, REMOVE_PROVIDER, CONFIGURE_FIREWALL, REMOVE_FIREWALL, MIGRATE_STORAGE, IS_PROVIDER_INSTALLED };

struct ElevatorCommand {
  ElevatorCommandType type{};
  std::vector<std::string> args{};
  std::vector<uint8_t> dataBytes{};

  [[nodiscard]] IPCMessage ToMessage() const {
    nlohmann::json json = {{"type", type}, {"args", args}};
    return {json.dump(-1, ' ', false, nlohmann::json::error_handler_t::replace), dataBytes};
  }

  [[nodiscard]] std::string ToString() const {
    return fmt::format("Type={}, DataSize={}", GetTypeName(type), dataBytes.size());
  }

  static std::string GetTypeName(ElevatorCommandType type) {
    switch(type) {
      case ElevatorCommandType::NONE:
        return "NONE";
      case ElevatorCommandType::RUN_CMD:
        return "RUN_CMD";
      case ElevatorCommandType::READ_BYTES:
        return "READ_BYTES";
      case ElevatorCommandType::WRITE_BYTES:
        return "WRITE_BYTES";
      case ElevatorCommandType::CREATE_FILE:
        return "CREATE_FILE";
      case ElevatorCommandType::REMOVE:
        return "REMOVE";
      case ElevatorCommandType::PROTECT_FILE:
        return "PROTECT_FILE";
      case ElevatorCommandType::EXISTS: return "EXISTS";
      case ElevatorCommandType::WRITE_ATOMIC: return "WRITE_ATOMIC";
      case ElevatorCommandType::INSTALL_PROVIDER: return "INSTALL_PROVIDER";
      case ElevatorCommandType::REMOVE_PROVIDER: return "REMOVE_PROVIDER";
      case ElevatorCommandType::CONFIGURE_FIREWALL: return "CONFIGURE_FIREWALL";
      case ElevatorCommandType::REMOVE_FIREWALL: return "REMOVE_FIREWALL";
      case ElevatorCommandType::MIGRATE_STORAGE: return "MIGRATE_STORAGE";
      case ElevatorCommandType::IS_PROVIDER_INSTALLED: return "IS_PROVIDER_INSTALLED";
    }
    return fmt::format("UNKNOWN({})", static_cast<int>(type));
  }

  static std::optional<ElevatorCommand> FromMessage(IPCMessage msg) {
    try {
      auto json = nlohmann::json::parse(msg.json);
      auto cmd = ElevatorCommand();
      cmd.type = json["type"];
      cmd.args = json["args"];
      cmd.dataBytes = std::move(msg.blob);
      return cmd;
    } catch(const std::exception &ex) {
      spdlog::error("Failed parsing elevator command.");
      return {};
    }
  }
};

struct ElevatorCommandResponse {
  bool isError{};
  std::string message{};
  ShellCmdResult cmdResult{};
  std::vector<uint8_t> dataBytes{};

  ElevatorCommandResponse() = default;
  explicit ElevatorCommandResponse(bool isError, const std::string &message) {
    this->isError = isError;
    this->message = message;
  }

  explicit ElevatorCommandResponse(std::vector<uint8_t> dataBytes) {
    this->dataBytes = std::move(dataBytes);
  }

  explicit ElevatorCommandResponse(const ShellCmdResult &cmdResult) {
    this->cmdResult = cmdResult;
  }

  [[nodiscard]] IPCMessage ToMessage() const {
    nlohmann::json json = {
        {"isError", isError},
        {"message", message},
        {"cmdResult", {{"exitCode", cmdResult.exitCode}, {"output", cmdResult.output}}},
    };
    return {json.dump(-1, ' ', false, nlohmann::json::error_handler_t::replace), dataBytes};
  }

  [[nodiscard]] std::string ToString() const {
    return fmt::format("IsError={}, Message='{}', ExitCode={}, DataSize={}", isError, message, cmdResult.exitCode, dataBytes.size());
  }

  static std::optional<ElevatorCommandResponse> FromMessage(IPCMessage msg) {
    try {
      auto json = nlohmann::json::parse(msg.json);
      auto resp = ElevatorCommandResponse();
      resp.isError = json["isError"];
      resp.message = json["message"];
      resp.cmdResult.exitCode = json["cmdResult"]["exitCode"];
      resp.cmdResult.output = json["cmdResult"]["output"];
      resp.dataBytes = std::move(msg.blob);
      return resp;
    } catch(const std::exception &ex) {
      spdlog::error("Failed parsing elevator response.");
      return {};
    }
  }
};

#endif
