#include "RestClient.h"
#include <regex>
#include <stdexcept>
#include <nlohmann/json.hpp>
#include "connection/web/HttpClient.h"

std::string RestClient::CheckForUpdates() {
  HttpOptions options;
  options.connectTimeout = std::chrono::seconds(5);
  options.transferTimeout = std::chrono::seconds(10);
  options.bodyLimit = 256 * 1024;
  options.maxRedirects = 0;
  HttpClient client;
  const auto response = client.Get("https://api.github.com/repos/Ladbaby/pcbu-desktop/releases/latest", options);
  if(!response.ok)
    throw std::runtime_error("Release check failed.");
  if(response.status == 404)
    return {};
  if(response.status != 200)
    throw std::runtime_error("GitHub release check was unavailable or rate limited.");
  try {
    const auto json = nlohmann::json::parse(response.body);
    if(json.at("draft").get<bool>() || json.at("prerelease").get<bool>())
      return {};
    auto tag = json.at("tag_name").get<std::string>();
    if(!std::regex_match(tag, std::regex(R"(^v?[0-9]{1,6}\.[0-9]{1,6}\.[0-9]{1,6}$)")))
      throw std::runtime_error("Unsupported release version.");
    if(tag.front() == 'v') tag.erase(0, 1);
    return tag;
  } catch(...) {
    throw std::runtime_error("Invalid stable release metadata.");
  }
}
