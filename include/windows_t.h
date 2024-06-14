#ifndef WINDOWS_T_H
#define WINDOWS_T_H

#include "c_types.h"

typedef byte*   LPCSTR;
typedef uint16* LPCWSTR;
typedef uint    HMODULE;
typedef uint    HANDLE;
typedef HANDLE* LPHANDLE;

typedef struct {
    uint32  OEMID;
    uint32  PageSize;
    uintptr MinimumApplicationAddress;
    uintptr MaximumApplicationAddress;
    uintptr ActiveProcessorMask;
    uint32  NumberOfProcessors;
    uint32  ProcessorType;
    uint32  AllocationGranularity;
    uint16  ProcessorLevel;
    uint16  ProcessorRevision;
} SYSTEM_INFO;

#ifdef _WIN64
typedef struct __declspec(align(16)) {
    uint64 Low; 
    int64  High;
} M128A;

typedef struct __declspec(align(16)) {
    uint64 P1Home;
    uint64 P2Home;
    uint64 P3Home;
    uint64 P4Home;
    uint64 P5Home;
    uint64 P6Home;
    uint32 ContextFlags;
    uint32 MxCSR;
    uint16 SegCS;
    uint16 SegDS;
    uint16 SegES;
    uint16 SegFS;
    uint16 SegGS;
    uint16 SegSS;
    uint32 EFlags;
    uint64 DR0;
    uint64 DR1;
    uint64 DR2;
    uint64 DR3;
    uint64 DR6;
    uint64 DR7;
    uint64 RAX;
    uint64 RCX;
    uint64 RDX;
    uint64 RBX;
    uint64 RSP;
    uint64 RBP;
    uint64 RSI;
    uint64 RDI;
    uint64 R8;
    uint64 R9;
    uint64 R10;
    uint64 R11;
    uint64 R12;
    uint64 R13;
    uint64 R14;
    uint64 R15;
    uint64 RIP;
    byte   Anon0[512];
    M128A  VectorRegister[26];
    uint64 VectorControl;
    uint64 DebugControl;
    uint64 LastBranchToRIP;
    uint64 LastBranchFromRIP;
    uint64 LastExceptionToRIP;
    uint64 LastExceptionFromRIP;
} CONTEXT;
#elif _WIN32
typedef struct __declspec(align(16)) {
    uint32 ControlWord;
    uint32 StatusWord;
	uint32 TagWord;
	uint32 ErrorOffset;
	uint32 ErrorSelector;
	uint32 DataOffset;
    uint32 DataSelector;
    uint8  RegisterArea[80];
    uint32 CR0NPXState;
} FSArea;

typedef struct __declspec(align(16)) {
    uint32 ContextFlags;
    uint32 DR0;
    uint32 DR1;
    uint32 DR2;
    uint32 DR3;
    uint32 DR6;
    uint32 DR7;
    FSArea FloatSave;
    uint32 SegGS;
    uint32 SegFS;
    uint32 SegES;
    uint32 SegDS;
    uint32 EDI;
    uint32 ESI;
    uint32 EBX;
    uint32 EDX;
    uint32 ECX;
    uint32 EAX;
    uint32 EBP;
    uint32 EIP;
    uint32 SegCS;
    uint32 EFlags;
    uint32 ESP;
    uint32 SegSS;
    uint8  ExtRegs[512];
} CONTEXT;
#endif

#define CURRENT_PROCESS (HANDLE)(-1)
#define CURRENT_THREAD  (HANDLE)(-2)

#define MEM_COMMIT   0x00001000
#define MEM_RESERVE  0x00002000
#define MEM_DECOMMIT 0x00004000
#define MEM_RELEASE  0x00008000

#define PAGE_NOACCESS          0x00000001
#define PAGE_READONLY          0x00000002
#define PAGE_READWRITE         0x00000004
#define PAGE_WRITECOPY         0x00000008
#define PAGE_EXECUTE           0x00000010
#define PAGE_EXECUTE_READ      0x00000020
#define PAGE_EXECUTE_READWRITE 0x00000040
#define PAGE_EXECUTE_WRITECOPY 0x00000080

#define CREATE_SUSPENDED 0x00000004

#define CONTEXT_AMD64 0x00100000
#define CONTEXT_i386  0x00010000

#ifdef _WIN64
#define CONTEXT_CONTROL (CONTEXT_AMD64 | 0x00000001)
#define CONTEXT_INTEGER (CONTEXT_AMD64 | 0x00000002)
#elif _WIN32
#define CONTEXT_CONTROL (CONTEXT_i386 | 0x00000001)
#define CONTEXT_INTEGER (CONTEXT_i386 | 0x00000002)
#endif

#define INFINITE      0xFFFFFFFF
#define WAIT_OBJECT_0 0x00000000

#define DUPLICATE_SAME_ACCESS 0x00000002

#define MAX_PATH 260

#define WSASYSNOTREADY 10091
#define WSAEINPROGRESS 10036

typedef void (*GetSystemInfo_t)
(
    SYSTEM_INFO* lpSystemInfo
);

typedef HMODULE (*LoadLibraryA_t)
(
    LPCSTR lpLibFileName
);

typedef HMODULE (*LoadLibraryW_t)
(
    LPCWSTR lpLibFileName
);

typedef HMODULE (*LoadLibraryExA_t)
(
    LPCSTR lpLibFileName, HANDLE hFile, uint32 dwFlags
);

typedef HMODULE(*LoadLibraryExW_t)
(
    LPCWSTR lpLibFileName, HANDLE hFile, uint32 dwFlags
);

typedef bool (*FreeLibrary_t)
(
    HMODULE hLibModule
);

typedef void (*FreeLibraryAndExitThread_t)
(
    HMODULE hLibModule, uint32 dwExitCode
);

typedef uintptr (*GetProcAddress_t)
(
    HMODULE hModule, LPCSTR lpProcName
);

typedef uintptr (*VirtualAlloc_t)
(
    uintptr lpAddress, uint dwSize, uint32 flAllocationType, uint32 flProtect
);

typedef bool (*VirtualFree_t)
(
    uintptr lpAddress, uint dwSize, uint32 dwFreeType
);

typedef bool (*VirtualProtect_t)
(
    uintptr lpAddress, uint dwSize, uint32 flNewProtect, uint32* lpflOldProtect
);

typedef uint (*VirtualQuery_t)
(
    uintptr lpAddress, uintptr lpBuffer, uint dwLength
);

typedef HANDLE (*CreateThread_t)
(
    uintptr lpThreadAttributes, uint dwStackSize, uintptr lpStartAddress,
    uintptr lpParameter, uint32 dwCreationFlags, uint32* lpThreadId
);

typedef void (*ExitThread_t)
(
    uint32 dwExitCode
);

typedef uint32 (*SuspendThread_t)
(
    HANDLE hThread
);

typedef uint32 (*ResumeThread_t)
(
    HANDLE hThread
);

typedef bool (*GetThreadContext_t)
(
    HANDLE hThread, CONTEXT* lpContext
);

typedef bool (*SetThreadContext_t)
(
    HANDLE hThread, CONTEXT* lpContext
);

typedef bool (*SwitchToThread_t)();

typedef uint32 (*GetThreadID_t)
(
    HANDLE hThread
);

typedef uint32 (*GetCurrentThreadID_t)();

typedef bool (*TerminateThread_t)
(
    HANDLE hThread, uint32 dwExitCode
);

typedef bool (*FlushInstructionCache_t)
(
    HANDLE hProcess, uintptr lpBaseAddress, uint dwSize
);

typedef HANDLE (*CreateMutexA_t)
(
    uintptr lpMutexAttributes, bool bInitialOwner, LPCSTR lpName
);

typedef bool (*ReleaseMutex_t)
(
    HANDLE hMutex
);

typedef uint32 (*WaitForSingleObject_t)
(
    HANDLE hHandle, uint32 dwMilliseconds
);

typedef bool (*DuplicateHandle_t)
(
    HANDLE hSourceProcessHandle, HANDLE hSourceHandle,
    HANDLE hTargetProcessHandle, LPHANDLE lpTargetHandle,
    uint32 dwDesiredAccess, bool bInheritHandle, uint32 dwOptions
);

typedef bool (*CloseHandle_t)
(
    HANDLE hObject
);

typedef int(*WSAStartup_t)
(
    uint16 wVersionRequired, void* lpWSAData
);

typedef int (*WSACleanup_t)();

#endif // WINDOWS_T_H
