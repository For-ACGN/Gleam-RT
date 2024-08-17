#ifndef WINDOWS_T_H
#define WINDOWS_T_H

#include "c_types.h"

typedef uint8  BYTE;
typedef uint16 WORD;
typedef uint32 DWORD;
typedef uint64 QWORD;

typedef int8  CHAR;
typedef int16 SHORT;
typedef int32 LONG;
typedef int64 LONGLONG;

typedef uint UINT;
typedef bool BOOL;
typedef uint SIZE_T;

typedef void* POINTER;
typedef void* HMODULE;
typedef void* HANDLE;
typedef void* FARPROC;

typedef void*   LPVOID;
typedef uint8*  LPSTR;
typedef uint16* LPWSTR;
typedef HANDLE* LPHANDLE;

typedef const void*   LPCVOID;
typedef const uint8*  LPCSTR;
typedef const uint16* LPCWSTR;

typedef struct {
    DWORD   OEMID;
    DWORD   PageSize;
    POINTER MinimumApplicationAddress;
    POINTER MaximumApplicationAddress;
    POINTER ActiveProcessorMask;
    DWORD   NumberOfProcessors;
    DWORD   ProcessorType;
    DWORD   AllocationGranularity;
    WORD    ProcessorLevel;
    WORD    ProcessorRevision;
} SYSTEM_INFO;

#ifdef _WIN64
typedef struct __declspec(align(16)) {
    QWORD    Low; 
    LONGLONG High;
} M128A;

typedef struct __declspec(align(16)) {
    QWORD P1Home;
    QWORD P2Home;
    QWORD P3Home;
    QWORD P4Home;
    QWORD P5Home;
    QWORD P6Home;
    DWORD ContextFlags;
    DWORD MxCSR;
    WORD  SegCS;
    WORD  SegDS;
    WORD  SegES;
    WORD  SegFS;
    WORD  SegGS;
    WORD  SegSS;
    DWORD EFlags;
    QWORD DR0;
    QWORD DR1;
    QWORD DR2;
    QWORD DR3;
    QWORD DR6;
    QWORD DR7;
    QWORD RAX;
    QWORD RCX;
    QWORD RDX;
    QWORD RBX;
    QWORD RSP;
    QWORD RBP;
    QWORD RSI;
    QWORD RDI;
    QWORD R8;
    QWORD R9;
    QWORD R10;
    QWORD R11;
    QWORD R12;
    QWORD R13;
    QWORD R14;
    QWORD R15;
    QWORD RIP;
    BYTE  Anon0[512];
    M128A VectorRegister[26];
    QWORD VectorControl;
    QWORD DebugControl;
    QWORD LastBranchToRIP;
    QWORD LastBranchFromRIP;
    QWORD LastExceptionToRIP;
    QWORD LastExceptionFromRIP;
} CONTEXT;
#elif _WIN32
typedef struct __declspec(align(16)) {
    DWORD ControlWord;
    DWORD StatusWord;
	DWORD TagWord;
	DWORD ErrorOffset;
	DWORD ErrorSelector;
	DWORD DataOffset;
    DWORD DataSelector;
    BYTE  RegisterArea[80];
    DWORD CR0NPXState;
} FS_AREA;

typedef struct __declspec(align(16)) {
    DWORD   ContextFlags;
    DWORD   DR0;
    DWORD   DR1;
    DWORD   DR2;
    DWORD   DR3;
    DWORD   DR6;
    DWORD   DR7;
    FS_AREA FloatSave;
    DWORD   SegGS;
    DWORD   SegFS;
    DWORD   SegES;
    DWORD   SegDS;
    DWORD   EDI;
    DWORD   ESI;
    DWORD   EBX;
    DWORD   EDX;
    DWORD   ECX;
    DWORD   EAX;
    DWORD   EBP;
    DWORD   EIP;
    DWORD   SegCS;
    DWORD   EFlags;
    DWORD   ESP;
    DWORD   SegSS;
    BYTE    ExtRegs[512];
} CONTEXT;
#endif

#define INVALID_HANDLE_VALUE (HANDLE)(-1)

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
#define WAIT_TIMEOUT  0x00000102
#define WAIT_FAILED   0xFFFFFFFF

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
    LPCSTR lpLibFileName, HANDLE hFile, DWORD dwFlags
);

typedef HMODULE(*LoadLibraryExW_t)
(
    LPCWSTR lpLibFileName, HANDLE hFile, DWORD dwFlags
);

typedef BOOL (*FreeLibrary_t)
(
    HMODULE hLibModule
);

typedef void (*FreeLibraryAndExitThread_t)
(
    HMODULE hLibModule, DWORD dwExitCode
);

typedef FARPROC (*GetProcAddress_t)
(
    HMODULE hModule, LPCSTR lpProcName
);

typedef LPVOID (*VirtualAlloc_t)
(
    LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect
);

typedef BOOL (*VirtualFree_t)
(
    LPVOID lpAddress, SIZE_T dwSize, DWORD dwFreeType
);

typedef BOOL (*VirtualProtect_t)
(
    LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, DWORD* lpflOldProtect
);

typedef SIZE_T (*VirtualQuery_t)
(
    LPCVOID lpAddress, POINTER lpBuffer, SIZE_T dwLength
);

typedef BOOL (*VirtualLock_t)
(
    LPVOID lpAddress, SIZE_T dwSize
);

typedef BOOL (*VirtualUnlock_t)
(
    LPVOID lpAddress, SIZE_T dwSize
);

typedef HANDLE (*CreateThread_t)
(
    POINTER lpThreadAttributes, SIZE_T dwStackSize, POINTER lpStartAddress,
    LPVOID lpParameter, DWORD dwCreationFlags, DWORD* lpThreadId
);

typedef void (*ExitThread_t)
(
    DWORD dwExitCode
);

typedef DWORD (*SuspendThread_t)
(
    HANDLE hThread
);

typedef DWORD (*ResumeThread_t)
(
    HANDLE hThread
);

typedef BOOL (*GetThreadContext_t)
(
    HANDLE hThread, CONTEXT* lpContext
);

typedef BOOL (*SetThreadContext_t)
(
    HANDLE hThread, CONTEXT* lpContext
);

typedef DWORD (*GetThreadID_t)
(
    HANDLE hThread
);

typedef DWORD (*GetCurrentThreadID_t)();

typedef BOOL (*TerminateThread_t)
(
    HANDLE hThread, DWORD dwExitCode
);

typedef BOOL (*FlushInstructionCache_t)
(
    HANDLE hProcess, LPCVOID lpBaseAddress, SIZE_T dwSize
);

typedef HANDLE (*CreateFileA_t)
(
    LPCSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode,
    POINTER lpSecurityAttributes, DWORD dwCreationDisposition,
    DWORD dwFlagsAndAttributes, HANDLE hTemplateFile
);

typedef HANDLE (*CreateFileW_t)
(
    LPCWSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode,
    POINTER lpSecurityAttributes, DWORD dwCreationDisposition,
    DWORD dwFlagsAndAttributes, HANDLE hTemplateFile
);

typedef HANDLE (*FindFirstFileA_t)
(
    LPCSTR lpFileName, POINTER lpFindFileData
);

typedef HANDLE (*FindFirstFileW_t)
(
    LPCWSTR lpFileName, POINTER lpFindFileData
);

typedef HANDLE (*FindFirstFileExA_t)
(
    LPCSTR lpFileName, UINT fInfoLevelId, LPVOID lpFindFileData,
    UINT fSearchOp, LPVOID lpSearchFilter, DWORD dwAdditionalFlags
);

typedef HANDLE (*FindFirstFileExW_t)
(
    LPCWSTR lpFileName, UINT fInfoLevelId, LPVOID lpFindFileData,
    UINT fSearchOp, LPVOID lpSearchFilter, DWORD dwAdditionalFlags
);

typedef BOOL (*FindClose_t)
(
    HANDLE hFindFile
);

typedef int(*WSAStartup_t)
(
    WORD wVersionRequired, POINTER lpWSAData
);

typedef int (*WSACleanup_t)();

typedef HANDLE (*CreateMutexA_t)
(
    POINTER lpMutexAttributes, BOOL bInitialOwner, LPCSTR lpName
);

typedef BOOL (*ReleaseMutex_t)
(
    HANDLE hMutex
);

typedef HANDLE (*CreateEventA_t)
(
    POINTER lpEventAttributes, BOOL bManualReset, BOOL bInitialState, LPCSTR lpName
);

typedef BOOL (*SetEvent_t)
(
    HANDLE hEvent
);

typedef BOOL (*ResetEvent_t)
(
    HANDLE hEvent
);

typedef DWORD (*WaitForSingleObject_t)
(
    HANDLE hHandle, DWORD dwMilliseconds
);

typedef BOOL (*DuplicateHandle_t)
(
    HANDLE hSourceProcessHandle, HANDLE hSourceHandle,
    HANDLE hTargetProcessHandle, LPHANDLE lpTargetHandle,
    DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwOptions
);

typedef BOOL (*CloseHandle_t)
(
    HANDLE hObject
);

#endif // WINDOWS_T_H
