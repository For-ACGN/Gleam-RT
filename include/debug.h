#ifndef DEBUG_H
#define DEBUG_H

#include "build.h"
#include "c_types.h"

#ifndef RELEASE_MODE

bool InitDebugModule();

void dbg_log(char* mod, char* fmt, ...);

#else

#define InitDebugModule() (true)

#define dbg_log(mod, fmt, ...)

#endif

#endif // DEBUG_H
