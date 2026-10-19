#include "Shell.h"

#include "shell/ElevatorService.h"
#include "shell/LocalShell.h"
#include "shell/WindowsOperations.h"

std::atomic<ElevatorService *> Shell::g_ElevatorService{};
std::function<void()> Shell::g_ElevatorLostHandler{};
std::mutex Shell::g_ElevatorLostMutex{};

void Shell::Init() {
  if(GetElevator() || LocalShell::IsRunningAsAdmin())
    return;
  g_ElevatorService.store(new ElevatorService(), std::memory_order_release);
}

void Shell::Destroy() {
  SetElevatorLostHandler({});
  delete g_ElevatorService.exchange(nullptr, std::memory_order_acq_rel);
}

void Shell::SetElevatorLostHandler(const std::function<void()> &handler) {
  std::unique_lock lock(g_ElevatorLostMutex);
  g_ElevatorLostHandler = handler;
}

ElevatorService *Shell::GetElevator() {
  return g_ElevatorService.load(std::memory_order_acquire);
}

bool Shell::HasAdmin() {
  auto elevator = GetElevator();
  return elevator ? elevator->IsRunning() : LocalShell::IsRunningAsAdmin();
}

ShellCmdResult Shell::RunCommand(const std::string &cmd) {
  auto elevator = GetElevator();
#ifdef WINDOWS
  return {-1, "Arbitrary elevated commands are disabled."};
#endif
  if(!elevator)
    return LocalShell::RunCommand(cmd);

  auto resp = Exec(*elevator, ElevatorCommandType::RUN_CMD, {cmd});
  if(resp.has_value())
    return resp.value().cmdResult;
  return {-1, "Elevator response timeout."};
}

bool Shell::CreateDir(const std::filesystem::path &path) {
  auto elevator = GetElevator();
  if(!elevator) {
#ifdef WINDOWS
    ElevatorCommand command;
    command.type = ElevatorCommandType::CREATE_FILE;
    command.args = {path.string(), "true"};

    auto response = WindowsOperations::Execute(command);
    if(response.isError) throw std::runtime_error(response.message);
    return true;
#else
    return LocalShell::CreateDir(path);
#endif
  }
  return Exec(*elevator, ElevatorCommandType::CREATE_FILE, {path.string(), "true"}).has_value();
}

bool Shell::CreateFile(const std::filesystem::path &path) {
  auto elevator = GetElevator();
  if(!elevator) {
#ifdef WINDOWS
    ElevatorCommand command;
    command.type = ElevatorCommandType::CREATE_FILE;
    command.args = {path.string(), "false"};

    auto response = WindowsOperations::Execute(command);
    if(response.isError) throw std::runtime_error(response.message);
    return true;
#else
    return LocalShell::CreateFile(path);
#endif
  }
  return Exec(*elevator, ElevatorCommandType::CREATE_FILE, {path.string(), "false"}).has_value();
}

bool Shell::Remove(const std::filesystem::path &path, bool recursive) {
  auto elevator = GetElevator();
  if(!elevator) {
#ifdef WINDOWS
    ElevatorCommand command;
    command.type = ElevatorCommandType::REMOVE;
    command.args = {path.string(), recursive ? "true" : "false"};

    auto response = WindowsOperations::Execute(command);
    if(response.isError) throw std::runtime_error(response.message);
    return true;
#else
    return LocalShell::Remove(path, recursive);
#endif
  }
  return Exec(*elevator, ElevatorCommandType::REMOVE, {path.string(), recursive ? "true" : "false"}).has_value();
}

std::vector<uint8_t> Shell::ReadBytes(const std::filesystem::path &path) {
  auto elevator = GetElevator();
  if(!elevator) {
#ifdef WINDOWS
    ElevatorCommand command;
    command.type = ElevatorCommandType::READ_BYTES;
    command.args = {path.string()};

    auto response = WindowsOperations::Execute(command);
    if(response.isError) throw std::runtime_error(response.message);
    return std::move(response.dataBytes);
#else
    return LocalShell::ReadBytes(path);
#endif
  }

  auto resp = Exec(*elevator, ElevatorCommandType::READ_BYTES, {path.string()});
  if(resp.has_value())
    return std::move(resp.value().dataBytes);
  return {};
}

bool Shell::WriteBytes(const std::filesystem::path &path, const std::vector<uint8_t> &data) {
  auto elevator = GetElevator();
  if(!elevator) {
#ifdef WINDOWS
    ElevatorCommand command;
    command.type = ElevatorCommandType::WRITE_BYTES;
    command.args = {path.string()};
    command.dataBytes = data;
    auto response = WindowsOperations::Execute(command);
    if(response.isError) throw std::runtime_error(response.message);
    return true;
#else
    return LocalShell::WriteBytes(path, data);
#endif
  }
  return Exec(*elevator, ElevatorCommandType::WRITE_BYTES, {path.string()}, data).has_value();
}

bool Shell::WindowsOperation(ElevatorCommandType type) {
#ifdef WINDOWS
  auto elevator = GetElevator();
  if(elevator) return Exec(*elevator,type,{}).has_value();
  ElevatorCommand command;
  command.type = type;
  auto response = WindowsOperations::Execute(command);
  if(response.isError) throw std::runtime_error(response.message);
  return true;
#else
  return false;
#endif
}

bool Shell::IsProviderInstalled() {
#ifdef WINDOWS
  auto elevator = GetElevator();
  if(elevator) {
    auto response = Exec(*elevator, ElevatorCommandType::IS_PROVIDER_INSTALLED, {});
    if(!response) throw std::runtime_error("Provider status response timeout.");
    return response->cmdResult.exitCode == 0;
  }
  ElevatorCommand command;
  command.type=ElevatorCommandType::IS_PROVIDER_INSTALLED;
  auto response=WindowsOperations::Execute(command);
  if(response.isError) throw std::runtime_error(response.message);
  return response.cmdResult.exitCode == 0;
#else
  return false;
#endif
}

bool Shell::Exists(const std::filesystem::path &path) {
  auto elevator = GetElevator();
  if(!elevator) {
#ifdef WINDOWS
    if(LocalShell::IsRunningAsAdmin()) {
      ElevatorCommand command;
      command.type = ElevatorCommandType::EXISTS;
      command.args = {path.string()};
      auto response = WindowsOperations::Execute(command);
      if(response.isError) throw std::runtime_error(response.message);
      return response.cmdResult.exitCode == 0;
    }
#endif
    return std::filesystem::exists(path);
  }
  auto resp = Exec(*elevator, ElevatorCommandType::EXISTS, {path.string()});
  if(!resp) throw std::runtime_error("Cannot inspect storage through helper.");
  return resp->cmdResult.exitCode == 0;
}

bool Shell::WriteBytesAtomic(const std::filesystem::path &path, const std::vector<uint8_t> &data) {
  auto elevator = GetElevator();
  if(!elevator) {
#ifdef WINDOWS
    ElevatorCommand command;
    command.type = ElevatorCommandType::WRITE_ATOMIC;
    command.args = {path.string()};
    command.dataBytes = data;
    auto response = WindowsOperations::Execute(command);
  if(response.isError) throw std::runtime_error(response.message);
  return true;
#else
    return LocalShell::WriteBytesAtomic(path, data);
#endif
  }
  return Exec(*elevator, ElevatorCommandType::WRITE_ATOMIC, {path.string()}, data).has_value();
}

bool Shell::ProtectFile(const std::filesystem::path &path, bool enabled) {
  auto elevator = GetElevator();
  if(!elevator) {
#ifdef WINDOWS
    ElevatorCommand command;
    command.type = ElevatorCommandType::PROTECT_FILE;
    command.args = {path.string(), enabled ? "true" : "false"};

    auto response = WindowsOperations::Execute(command);
    if(response.isError) throw std::runtime_error(response.message);
    return true;
#else
    return LocalShell::ProtectFile(path, enabled);
#endif
  }
  return Exec(*elevator, ElevatorCommandType::PROTECT_FILE, {path.string(), enabled ? "true" : "false"}).has_value();
}

std::optional<ElevatorCommandResponse> Shell::Exec(ElevatorService &elevator, ElevatorCommandType type, std::vector<std::string> args,
                                                   std::vector<uint8_t> data) {
  auto req = ElevatorCommand();
  req.type = type;
  req.args = std::move(args);
  req.dataBytes = std::move(data);
  auto resp = elevator.ExecCommand(req);
  if(!resp.has_value() && !elevator.IsRunning())
    OnElevatorLost();
  if(!resp.has_value()) throw std::runtime_error("Stage=ipc.response, Code=1460");
#ifdef WINDOWS
  if(resp->isError) throw std::runtime_error(resp->message);
#else
  if(resp->isError) return {};
#endif
  return resp;
}

void Shell::OnElevatorLost() {
  std::function<void()> handler{};
  {
    std::unique_lock lock(g_ElevatorLostMutex);
    handler = std::move(g_ElevatorLostHandler);
    g_ElevatorLostHandler = {};
  }
  if(handler)
    handler();
}
