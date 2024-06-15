@echo off

echo =======================================================
echo Get Hash Tool from https://github.com/For-ACGN/hash_api
echo =======================================================
echo.

echo Runtime core
hash -fmt 64 -conc -func GetSystemInfo
hash -fmt 64 -conc -func FlushInstructionCache
hash -fmt 64 -conc -func CreateMutexA
hash -fmt 64 -conc -func ReleaseMutex
hash -fmt 64 -conc -func CreateEventA
hash -fmt 64 -conc -func SetEvent
hash -fmt 64 -conc -func ResetEvent
hash -fmt 64 -conc -func WaitForSingleObject
hash -fmt 64 -conc -func DuplicateHandle
hash -fmt 64 -conc -func CloseHandle
echo.

echo Runtime IAT Hooks
hash -fmt 64 -conc -func GetProcAddress
hash -fmt 64 -conc -func RT_GetProcAddressByName
hash -fmt 64 -conc -func RT_GetProcAddressByHash
hash -fmt 64 -conc -func RT_GetProcAddressOriginal
hash -fmt 64 -conc -func Sleep
echo.

echo Library Tracker
hash -fmt 64 -conc -func LoadLibraryA
hash -fmt 64 -conc -func LoadLibraryW
hash -fmt 64 -conc -func LoadLibraryExA
hash -fmt 64 -conc -func LoadLibraryExW
hash -fmt 64 -conc -func FreeLibrary
hash -fmt 64 -conc -func FreeLibraryAndExitThread
echo.

echo Memory Tracker
hash -fmt 64 -conc -func VirtualAlloc
hash -fmt 64 -conc -func VirtualFree
hash -fmt 64 -conc -func VirtualProtect
hash -fmt 64 -conc -func VirtualQuery
echo.

echo Thread Tracker
hash -fmt 64 -conc -func CreateThread
hash -fmt 64 -conc -func ExitThread
hash -fmt 64 -conc -func SuspendThread
hash -fmt 64 -conc -func ResumeThread
hash -fmt 64 -conc -func GetThreadContext
hash -fmt 64 -conc -func SetThreadContext
hash -fmt 64 -conc -func SwitchToThread
hash -fmt 64 -conc -func GetThreadId
hash -fmt 64 -conc -func GetCurrentThreadId
hash -fmt 64 -conc -func TerminateThread
echo.

echo Resource Tracker
hash -fmt 64 -conc -mod ws2_32.dll -func WSAStartup
hash -fmt 64 -conc -mod ws2_32.dll -func WSACleanup
echo.

echo.

echo Runtime Core
hash -fmt 32 -conc -func GetSystemInfo
hash -fmt 32 -conc -func FlushInstructionCache
hash -fmt 32 -conc -func CreateMutexA
hash -fmt 32 -conc -func ReleaseMutex
hash -fmt 32 -conc -func CreateEventA
hash -fmt 32 -conc -func SetEvent
hash -fmt 32 -conc -func ResetEvent
hash -fmt 32 -conc -func WaitForSingleObject
hash -fmt 32 -conc -func DuplicateHandle
hash -fmt 32 -conc -func CloseHandle
echo.

echo Runtime IAT Hooks
hash -fmt 32 -conc -func GetProcAddress
hash -fmt 32 -conc -func RT_GetProcAddressByName
hash -fmt 32 -conc -func RT_GetProcAddressByHash
hash -fmt 32 -conc -func RT_GetProcAddressOriginal
hash -fmt 32 -conc -func Sleep
echo.

echo Library Tracker
hash -fmt 32 -conc -func LoadLibraryA
hash -fmt 32 -conc -func LoadLibraryW
hash -fmt 32 -conc -func LoadLibraryExA
hash -fmt 32 -conc -func LoadLibraryExW
hash -fmt 32 -conc -func FreeLibrary
hash -fmt 32 -conc -func FreeLibraryAndExitThread
echo.

echo Memory Tracker
hash -fmt 32 -conc -func VirtualAlloc
hash -fmt 32 -conc -func VirtualFree
hash -fmt 32 -conc -func VirtualProtect
hash -fmt 32 -conc -func VirtualQuery
echo.

echo Thread Tracker
hash -fmt 32 -conc -func CreateThread
hash -fmt 32 -conc -func ExitThread
hash -fmt 32 -conc -func SuspendThread
hash -fmt 32 -conc -func ResumeThread
hash -fmt 32 -conc -func GetThreadContext
hash -fmt 32 -conc -func SetThreadContext
hash -fmt 32 -conc -func SwitchToThread
hash -fmt 32 -conc -func GetThreadId
hash -fmt 32 -conc -func GetCurrentThreadId
hash -fmt 32 -conc -func TerminateThread
echo.

echo Resource Tracker
hash -fmt 32 -conc -mod ws2_32.dll -func WSAStartup
hash -fmt 32 -conc -mod ws2_32.dll -func WSACleanup
echo.

pause
