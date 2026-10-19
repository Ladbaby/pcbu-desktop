#pragma once
#ifdef WINDOWS
namespace WindowsProvider {
bool Install();
bool Remove();
bool IsInstalled();
}
#endif
