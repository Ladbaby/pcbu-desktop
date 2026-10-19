#pragma once
#ifdef WINDOWS
#include "ElevatorCommands.h"
// Both the helper and already-elevated desktop use the same command authorization.
namespace WindowsOperations {
bool ValidateCommand(const ElevatorCommand &command);
ElevatorCommandResponse Execute(const ElevatorCommand &command);
}
#endif
