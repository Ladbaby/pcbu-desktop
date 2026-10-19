#include "LoggingSystem.h"

#include <filesystem>
#include <fstream>
#include <spdlog/sinks/rotating_file_sink.h>
#include <spdlog/sinks/stdout_sinks.h>
#include <vector>

#include "AppSettings.h"
#include "shell/LocalShell.h"
#include "shell/Shell.h"

std::string LoggingSystem::g_LogName{};

void LoggingSystem::Init(const std::string &logName, bool printToConsole, bool writeToFile) {
  g_LogName = logName;
#ifdef WINDOWS
  // Rotating sinks reopen/rename filenames and cannot retain the verified file handle.
  // Until a handle-safe Windows sink exists, do not let elevated/LogonUI logging
  // follow attacker-precreated directory entries or hard links. Console and IPC
  // stage diagnostics remain available; unprivileged user logs still rotate.
  if(LocalShell::IsRunningAsAdmin()) writeToFile = false;
#endif
  auto logsDir = AppSettings::GetLogsDir(!LocalShell::IsRunningAsAdmin());
  auto logPath = logsDir / fmt::format("{}.log", g_LogName);
  if(writeToFile) {
    if(!std::filesystem::exists(logsDir))
      LocalShell::CreateDir(logsDir);
  }

  try {
    bool enableDebug = false;
    if(writeToFile || printToConsole) {
      try { enableDebug = Shell::Exists(AppSettings::GetBaseDir() / "LOG_DEBUG"); }
      catch(...) { /* Logging must not prevent startup or recovery. */ }
    }
    auto logLevel = enableDebug ? spdlog::level::debug : spdlog::level::info;

    std::vector<spdlog::sink_ptr> sinks{};
    if(printToConsole) {
      auto consoleSink = std::make_shared<spdlog::sinks::stdout_sink_mt>();
      consoleSink->set_level(logLevel);
      sinks.push_back(consoleSink);
    }
    if(writeToFile) {
      auto fileSink = std::make_shared<spdlog::sinks::rotating_file_sink_mt>(logPath.string(), 1024 * 1024, 3, false);
      fileSink->set_level(logLevel);
      sinks.push_back(fileSink);
    }

    auto loggerPtr = std::make_shared<spdlog::logger>(LOGGER_NAME, sinks.begin(), sinks.end());
    loggerPtr->set_pattern("[%Y-%m-%d %H:%M:%S.%e] [%l] %v");
    loggerPtr->set_level(logLevel);
    spdlog::set_default_logger(loggerPtr);
    spdlog::flush_on(logLevel);
    spdlog::info("Logger init.");
  } catch(const std::exception &) {
    spdlog::error("Error initializing logger.");
  }
}

void LoggingSystem::Destroy() {
  spdlog::info("Logger destroy.");
  auto nullLogger = std::make_shared<spdlog::logger>(NULL_LOGGER_NAME);
  nullLogger->set_level(spdlog::level::off);
  spdlog::set_default_logger(nullLogger);
  spdlog::drop(LOGGER_NAME);
  g_LogName = {};
}
