#ifndef DEBUG_H
#define DEBUG_H

#include "c_types.h"

bool InitDebugModule();

void dbg_log(char* mod, char* fmt, ...);

#endif // DEBUG_H
