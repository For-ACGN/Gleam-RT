#ifndef DEBUG_H
#define DEBUG_H

#include "build.h"
#include "c_types.h"

#ifdef RELEASE_MODE
    #define NAME_RT_MUTEX_GLOBAL  NULL
    #define NAME_RT_MUTEX_SLEEP   NULL
    #define NAME_RT_EVENT_ARRIVE  NULL
    #define NAME_RT_EVENT_DONE    NULL
    #define NAME_RT_MUTEX_EVENT   NULL
    #define NAME_RT_TIMER_SLEEP   NULL
    #define NAME_RT_TIMER_SLEEPHR NULL
#else
#ifdef _WIN64
    #define NAME_RT_MUTEX_GLOBAL  "RT_Core_Global_x64"
    #define NAME_RT_MUTEX_SLEEP   "RT_Core_Sleep_x64"
    #define NAME_RT_EVENT_ARRIVE  "RT_Core_Arrive_x64"
    #define NAME_RT_EVENT_DONE    "RT_Core_Done_x64"
    #define NAME_RT_MUTEX_EVENT   "RT_Core_Event_x64"
    #define NAME_RT_TIMER_SLEEP   L"RT_Method_Sleep_x64"
    #define NAME_RT_TIMER_SLEEPHR L"RT_Method_SleepHR_x64"
#elif _WIN32
    #define NAME_RT_MUTEX_GLOBAL  "RT_Core_Global_x86"
    #define NAME_RT_MUTEX_SLEEP   "RT_Core_Sleep_x86"
    #define NAME_RT_EVENT_ARRIVE  "RT_Core_Arrive_x86"
    #define NAME_RT_EVENT_DONE    "RT_Core_Done_x86"
    #define NAME_RT_MUTEX_EVENT   "RT_Core_Event_x86"
    #define NAME_RT_TIMER_SLEEP   L"RT_Method_Sleep_x86"
    #define NAME_RT_TIMER_SLEEPHR L"RT_Method_SleepHR_x86"
#endif
#endif // RELEASE_MODE

#ifndef RELEASE_MODE

bool InitDebugger();

void dbg_log(char* mod, char* fmt, ...);

#else

#define InitDebugger() (true)

#define dbg_log(mod, fmt, ...)

#endif

#endif // DEBUG_H
