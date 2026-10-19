#ifndef PCBU_DESKTOP_RESTCLIENT_H
#define PCBU_DESKTOP_RESTCLIENT_H
#include <string>
class RestClient {
public:
  // Empty means no stable release is published. Errors throw without response contents.
  static std::string CheckForUpdates();
};
#endif
