@echo off

echo ==================================================================
echo Build HashAPI tool from https://github.com/RSSU-Shellcode/hash_api
echo ==================================================================
echo.

echo ------------------------x64------------------------

echo [Runtime Core]
hash_api -fmt 64 -conc -func GetSystemInfo
hash_api -fmt 64 -conc -func FlushInstructionCache
hash_api -fmt 64 -conc -func SetCurrentDirectoryA
hash_api -fmt 64 -conc -func SetCurrentDirectoryW
hash_api -fmt 64 -conc -func CreateMutexA
hash_api -fmt 64 -conc -func ReleaseMutex
hash_api -fmt 64 -conc -func CreateEventA
hash_api -fmt 64 -conc -func SetEvent
hash_api -fmt 64 -conc -func ResetEvent
hash_api -fmt 64 -conc -func CreateWaitableTimerW
hash_api -fmt 64 -conc -func SetWaitableTimer
hash_api -fmt 64 -conc -func WaitForSingleObject
hash_api -fmt 64 -conc -func DuplicateHandle
hash_api -fmt 64 -conc -func CloseHandle
echo.

echo [Runtime Methods]
hash_api -fmt 64 -conc -func RT_GetProcAddressByName
hash_api -fmt 64 -conc -func RT_GetProcAddressByHash
hash_api -fmt 64 -conc -func RT_GetProcAddressOriginal
hash_api -fmt 64 -conc -func RT_GetArgValue
hash_api -fmt 64 -conc -func RT_GetArgPointer
hash_api -fmt 64 -conc -func RT_EraseArgument
hash_api -fmt 64 -conc -func RT_EraseAllArgs
echo.

echo [Runtime IAT Hooks]
hash_api -fmt 64 -conc -func GetProcAddress
hash_api -fmt 64 -conc -func ExitProcess
hash_api -fmt 64 -conc -func Sleep
hash_api -fmt 64 -conc -func SleepEx
echo.

echo [Library Tracker]
hash_api -fmt 64 -conc -func LoadLibraryA
hash_api -fmt 64 -conc -func LoadLibraryW
hash_api -fmt 64 -conc -func LoadLibraryExA
hash_api -fmt 64 -conc -func LoadLibraryExW
hash_api -fmt 64 -conc -func FreeLibrary
hash_api -fmt 64 -conc -func FreeLibraryAndExitThread
echo.

echo [Memory Tracker]
hash_api -fmt 64 -conc -func VirtualAlloc
hash_api -fmt 64 -conc -func VirtualFree
hash_api -fmt 64 -conc -func VirtualProtect
hash_api -fmt 64 -conc -func VirtualQuery
hash_api -fmt 64 -conc -func VirtualLock
hash_api -fmt 64 -conc -func VirtualUnlock
hash_api -fmt 64 -conc -mod msvcrt.dll -func malloc
hash_api -fmt 64 -conc -mod msvcrt.dll -func calloc
hash_api -fmt 64 -conc -mod msvcrt.dll -func realloc
hash_api -fmt 64 -conc -mod msvcrt.dll -func free
echo.

echo [Thread Tracker]
hash_api -fmt 64 -conc -func CreateThread
hash_api -fmt 64 -conc -func ExitThread
hash_api -fmt 64 -conc -func SuspendThread
hash_api -fmt 64 -conc -func ResumeThread
hash_api -fmt 64 -conc -func GetThreadContext
hash_api -fmt 64 -conc -func SetThreadContext
hash_api -fmt 64 -conc -func GetThreadId
hash_api -fmt 64 -conc -func GetCurrentThreadId
hash_api -fmt 64 -conc -func TerminateThread
echo.

echo [Resource Tracker]
hash_api -fmt 64 -conc -func CreateFileA
hash_api -fmt 64 -conc -func CreateFileW
hash_api -fmt 64 -conc -func FindFirstFileA
hash_api -fmt 64 -conc -func FindFirstFileW
hash_api -fmt 64 -conc -func FindFirstFileExA
hash_api -fmt 64 -conc -func FindFirstFileExW
hash_api -fmt 64 -conc -func FindClose
hash_api -fmt 64 -conc -mod ws2_32.dll -func WSAStartup
hash_api -fmt 64 -conc -mod ws2_32.dll -func WSACleanup
echo.

echo [Win File Module]
hash_api -fmt 64 -conc -func CreateFileA
hash_api -fmt 64 -conc -func CreateFileW
hash_api -fmt 64 -conc -func GetFileSizeEx
hash_api -fmt 64 -conc -func ReadFile
hash_api -fmt 64 -conc -func WriteFile
echo.

echo ------------------------x86------------------------

echo [Runtime Core]
hash_api -fmt 32 -conc -func GetSystemInfo
hash_api -fmt 32 -conc -func FlushInstructionCache
hash_api -fmt 32 -conc -func SetCurrentDirectoryA
hash_api -fmt 32 -conc -func SetCurrentDirectoryW
hash_api -fmt 32 -conc -func CreateMutexA
hash_api -fmt 32 -conc -func ReleaseMutex
hash_api -fmt 32 -conc -func CreateEventA
hash_api -fmt 32 -conc -func SetEvent
hash_api -fmt 32 -conc -func ResetEvent
hash_api -fmt 32 -conc -func CreateWaitableTimerW
hash_api -fmt 32 -conc -func SetWaitableTimer
hash_api -fmt 32 -conc -func WaitForSingleObject
hash_api -fmt 32 -conc -func DuplicateHandle
hash_api -fmt 32 -conc -func CloseHandle
echo.

echo [Runtime Methods]
hash_api -fmt 32 -conc -func RT_GetProcAddressByName
hash_api -fmt 32 -conc -func RT_GetProcAddressByHash
hash_api -fmt 32 -conc -func RT_GetProcAddressOriginal
hash_api -fmt 32 -conc -func RT_GetArgValue
hash_api -fmt 32 -conc -func RT_GetArgPointer
hash_api -fmt 32 -conc -func RT_EraseArgument
hash_api -fmt 32 -conc -func RT_EraseAllArgs
echo.

echo [Runtime IAT Hooks]
hash_api -fmt 32 -conc -func GetProcAddress
hash_api -fmt 32 -conc -func ExitProcess
hash_api -fmt 32 -conc -func Sleep
hash_api -fmt 32 -conc -func SleepEx
echo.

echo [Library Tracker]
hash_api -fmt 32 -conc -func LoadLibraryA
hash_api -fmt 32 -conc -func LoadLibraryW
hash_api -fmt 32 -conc -func LoadLibraryExA
hash_api -fmt 32 -conc -func LoadLibraryExW
hash_api -fmt 32 -conc -func FreeLibrary
hash_api -fmt 32 -conc -func FreeLibraryAndExitThread
echo.

echo [Memory Tracker]
hash_api -fmt 32 -conc -func VirtualAlloc
hash_api -fmt 32 -conc -func VirtualFree
hash_api -fmt 32 -conc -func VirtualProtect
hash_api -fmt 32 -conc -func VirtualQuery
hash_api -fmt 32 -conc -func VirtualLock
hash_api -fmt 32 -conc -func VirtualUnlock
hash_api -fmt 32 -conc -mod msvcrt.dll -func malloc
hash_api -fmt 32 -conc -mod msvcrt.dll -func calloc
hash_api -fmt 32 -conc -mod msvcrt.dll -func realloc
hash_api -fmt 32 -conc -mod msvcrt.dll -func free
echo.

echo [Thread Tracker]
hash_api -fmt 32 -conc -func CreateThread
hash_api -fmt 32 -conc -func ExitThread
hash_api -fmt 32 -conc -func SuspendThread
hash_api -fmt 32 -conc -func ResumeThread
hash_api -fmt 32 -conc -func GetThreadContext
hash_api -fmt 32 -conc -func SetThreadContext
hash_api -fmt 32 -conc -func GetThreadId
hash_api -fmt 32 -conc -func GetCurrentThreadId
hash_api -fmt 32 -conc -func TerminateThread
echo.

echo [Resource Tracker]
hash_api -fmt 32 -conc -func CreateFileA
hash_api -fmt 32 -conc -func CreateFileW
hash_api -fmt 32 -conc -func FindFirstFileA
hash_api -fmt 32 -conc -func FindFirstFileW
hash_api -fmt 32 -conc -func FindFirstFileExA
hash_api -fmt 32 -conc -func FindFirstFileExW
hash_api -fmt 32 -conc -func FindClose
hash_api -fmt 32 -conc -mod ws2_32.dll -func WSAStartup
hash_api -fmt 32 -conc -mod ws2_32.dll -func WSACleanup
echo.

echo [Win File Module]
hash_api -fmt 32 -conc -func CreateFileA
hash_api -fmt 32 -conc -func CreateFileW
hash_api -fmt 32 -conc -func GetFileSizeEx
hash_api -fmt 32 -conc -func ReadFile
hash_api -fmt 32 -conc -func WriteFile
echo.

pause
