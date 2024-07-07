#include "build.h"
#include "c_types.h"
#include "debug.h"

#ifdef IS_RELEASE

void dbg_log(char* mod, char* fmt, ...){};

#else

#include <stdio.h>
#include <stdarg.h>

void dbg_log(char* mod, char* fmt, ...)
{
    va_list args;
    va_start(args, fmt);

    printf_s("%s ", mod);
    printf_s(fmt, args);

    va_end(args);
}

#endif
