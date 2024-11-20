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
typedef void* PVOID;
typedef void* HANDLE;
typedef void* FARPROC;

typedef void*   LPVOID;
typedef uint8*  LPSTR;
typedef uint16* LPWSTR;
typedef HANDLE* LPHANDLE;

typedef const void*   LPCVOID;
typedef const uint8*  LPCSTR;
typedef const uint16* LPCWSTR;

typedef void* HMODULE;
typedef void* HGLOBAL;
typedef void* HLOCAL;
typedef void* HINTERNET;

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

typedef struct {
    PVOID lpData;
    DWORD cbData;
    BYTE  cbOverhead;
    BYTE  iRegionIndex;
    WORD  wFlags;
    union {
        struct {
            HANDLE hMem;
            DWORD  dwReserved[3];
        } Block;
        struct {
            DWORD  dwCommittedSize;
            DWORD  dwUnCommittedSize;
            LPVOID lpFirstBlock;
            LPVOID lpLastBlock;
        } Region;
    } DUMMYUNIONNAME;
} HEAP_ENTRY;

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
typedef struct {
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

typedef struct {
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

typedef struct {
    DWORD  dwStructSize;
    LPWSTR lpszScheme;
    DWORD  dwSchemeLength;
    DWORD  nScheme;
    LPWSTR lpszHostName;
    DWORD  dwHostNameLength;
    WORD   nPort;
    LPWSTR lpszUserName;
    DWORD  dwUserNameLength;
    LPWSTR lpszPassword;
    DWORD  dwPasswordLength;
    LPWSTR lpszUrlPath;
    DWORD  dwUrlPathLength;
    LPWSTR lpszExtraInfo;
    DWORD  dwExtraInfoLength;
} URL_COMPONENTS;

#define MAX_PATH 260

#define INVALID_HANDLE_VALUE ((HANDLE)(-1))

#define CURRENT_PROCESS ((HANDLE)(-1))
#define CURRENT_THREAD  ((HANDLE)(-2))

#define ERROR_NO_MORE_ITEMS 259

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

#define PROCESS_HEAP_REGION            0x0001
#define PROCESS_HEAP_UNCOMMITTED_RANGE 0x0002
#define PROCESS_HEAP_ENTRY_BUSY        0x0004

#define GMEM_FIXED    0x0000
#define GMEM_MOVEABLE 0x0002
#define GMEM_ZEROINIT 0x0040
#define GPTR          0x0040
#define GHND          0x0042

#define LMEM_FIXED    0x0000
#define LMEM_MOVEABLE 0x0002
#define LMEM_ZEROINIT 0x0040
#define LPTR          0x0040
#define LHND          0x0042

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

#define INFINITE       0xFFFFFFFF
#define WAIT_ABANDONED 0x00000080
#define WAIT_OBJECT_0  0x00000000
#define WAIT_TIMEOUT   0x00000102
#define WAIT_FAILED    0xFFFFFFFF

#define DUPLICATE_SAME_ACCESS 0x00000002

#define GENERIC_ALL     0x10000000
#define GENERIC_EXECUTE 0x20000000
#define GENERIC_WRITE   0x40000000
#define GENERIC_READ    0x80000000

#define FILE_SHARE_DELETE 0x00000004
#define FILE_SHARE_READ   0x00000001
#define FILE_SHARE_WRITE  0x00000002

#define CREATE_ALWAYS     2
#define CREATE_NEW        1
#define OPEN_ALWAYS       4
#define OPEN_EXISTING     3
#define TRUNCATE_EXISTING 5 

#define FILE_ATTRIBUTE_ARCHIVE   0x20
#define FILE_ATTRIBUTE_ENCRYPTED 0x4000
#define FILE_ATTRIBUTE_HIDDEN    0x2
#define FILE_ATTRIBUTE_NORMAL    0x80
#define FILE_ATTRIBUTE_OFFLINE   0x1000
#define FILE_ATTRIBUTE_READONLY  0x1
#define FILE_ATTRIBUTE_SYSTEM    0x4
#define FILE_ATTRIBUTE_TEMPORARY 0x100

#define FILE_FLAG_DELETE_ON_CLOSE 0x04000000
#define FILE_FLAG_NO_BUFFERING    0x20000000
#define FILE_FLAG_WRITE_THROUGH   0x80000000

#define WSASYSNOTREADY 10091
#define WSAEINPROGRESS 10036

#define CP_ACP 0

#define INTERNET_SCHEME_HTTP  1
#define INTERNET_SCHEME_HTTPS 2

#define WINHTTP_OPTION_DECOMPRESSION 0x00000076

#define WINHTTP_DECOMPRESSION_FLAG_GZIP    1
#define WINHTTP_DECOMPRESSION_FLAG_DEFLATE 2
#define WINHTTP_DECOMPRESSION_FLAG_ALL     3

#define WINHTTP_ACCESS_TYPE_DEFAULT_PROXY   0
#define WINHTTP_ACCESS_TYPE_NO_PROXY        1
#define WINHTTP_ACCESS_TYPE_NAMED_PROXY     3
#define WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY 4

#define WINHTTP_NO_REFERER            NULL
#define WINHTTP_DEFAULT_ACCEPT_TYPES  NULL
#define WINHTTP_NO_ADDITIONAL_HEADERS NULL
#define WINHTTP_NO_REQUEST_DATA       NULL

#define WINHTTP_FLAG_SECURE 0x00800000

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

typedef HANDLE (*GetProcessHeap_t)();

typedef DWORD (*GetProcessHeaps_t)
(
    DWORD NumberOfHeaps, HANDLE* ProcessHeaps
);

typedef HANDLE (*HeapCreate_t)
(
    DWORD flOptions, SIZE_T dwInitialSize, SIZE_T dwMaximumSize
);

typedef BOOL (*HeapDestroy_t)
(
    HANDLE hHeap
);

typedef LPVOID (*HeapAlloc_t)
(
    HANDLE hHeap, DWORD dwFlags, SIZE_T dwBytes
);

typedef LPVOID (*HeapReAlloc_t)
(
    HANDLE hHeap, DWORD dwFlags, LPVOID lpMem, SIZE_T dwBytes
);

typedef BOOL (*HeapFree_t)
(
    HANDLE hHeap, DWORD dwFlags, LPVOID lpMem
);

typedef SIZE_T (*HeapSize_t)
(
    HANDLE hHeap, DWORD dwFlags, LPCVOID lpMem
);

typedef BOOL (*HeapLock_t)
(
    HANDLE hHeap
);

typedef BOOL (*HeapUnlock_t)
(
    HANDLE hHeap
);

typedef BOOL (*HeapWalk_t)
(
    HANDLE hHeap, HEAP_ENTRY* lpEntry
);

typedef HGLOBAL (*GlobalAlloc_t)
(
    UINT uFlags, SIZE_T dwBytes
);

typedef HGLOBAL (*GlobalReAlloc_t)
(
    HGLOBAL hMem, SIZE_T dwBytes, UINT uFlags
);

typedef HGLOBAL (*GlobalFree_t)
(
    HGLOBAL lpMem
);

typedef HLOCAL (*LocalAlloc_t)
(
    UINT uFlags, SIZE_T dwBytes
);

typedef HLOCAL (*LocalReAlloc_t)
(
    HLOCAL hMem, SIZE_T dwBytes, UINT uFlags
);

typedef HLOCAL (*LocalFree_t)
(
    HLOCAL lpMem
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

typedef BOOL (*SetCurrentDirectoryA_t)
(
    LPSTR lpPathName
);

typedef BOOL (*SetCurrentDirectoryW_t)
(
    LPWSTR lpPathName
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

typedef BOOL (*GetFileSizeEx_t)
(
    HANDLE hFile, LONGLONG* lpFileSize
);

typedef BOOL (*ReadFile_t)
(
    HANDLE hFile, LPVOID lpBuffer, DWORD nNumberOfBytesToRead,
    DWORD* lpNumberOfBytesRead, POINTER lpOverlapped
);

typedef BOOL (*WriteFile_t)
(
    HANDLE hFile, LPCVOID lpBuffer, DWORD nNumberOfBytesToWrite,
    DWORD* lpNumberOfBytesWritten, POINTER lpOverlapped
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

typedef HANDLE (*CreateWaitableTimerW_t)
(
    POINTER lpTimerAttributes, BOOL bManualReset, LPCWSTR lpTimerName
);

typedef BOOL (*SetWaitableTimer_t)
(
    HANDLE hTimer, LONGLONG* lpDueTime, LONG lPeriod,
    LPVOID pfnCompletionRoutine, LPVOID lpArgToCompletionRoutine,
    BOOL fResume
);

typedef void (*Sleep_t)
(
    DWORD dwMilliseconds
);

typedef DWORD (*SleepEx_t)
(
    DWORD dwMilliseconds, BOOL bAlertable
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

typedef int (*MultiByteToWideChar_t)
(
    UINT CodePage, DWORD dwFlags, LPSTR lpMultiByteStr, 
    int cbMultiByte, LPWSTR lpWideCharStr, int cchWideChar
);

typedef int (*WideCharToMultiByte_t)
(
    UINT CodePage, DWORD dwFlags, LPWSTR lpWideCharStr,
    int cchWideChar, LPSTR lpMultiByteStr, int cbMultiByte,
    byte* lpDefaultChar, BOOL* lpUsedDefaultChar
);

typedef BOOL (*WinHttpCrackUrl_t)
(
    LPCWSTR pwszUrl, DWORD dwUrlLength, DWORD dwFlags,
    URL_COMPONENTS* lpUrlComponents
);

typedef HINTERNET (*WinHttpOpen_t)
(
    LPCWSTR pszAgentW, DWORD dwAccessType, LPCWSTR pszProxyW,
    LPCWSTR pszProxyBypassW, DWORD dwFlags
);

typedef HINTERNET (*WinHttpConnect_t)
(
    HINTERNET hSession, LPCWSTR pswzServerName, WORD nServerPort,
    DWORD dwReserved
);

typedef BOOL (*WinHttpSetOption_t)
(
    HINTERNET hInternet, DWORD dwOption, LPVOID lpBuffer, DWORD dwBufferLength
);

typedef BOOL (*WinHttpSetTimeouts_t)
(
    HINTERNET hInternet, int nResolveTimeout, int nConnectTimeout,
    int nSendTimeout, int nReceiveTimeout
);

typedef HINTERNET (*WinHttpOpenRequest_t)
(
    HINTERNET hConnect, LPCWSTR pwszVerb, LPCWSTR pwszObjectName,
    LPCWSTR pwszVersion, LPCWSTR pwszReferrer, LPCWSTR* ppwszAcceptTypes, 
    DWORD dwFlags
);

typedef BOOL (*WinHttpSetCredentials_t)
(
    HINTERNET hRequest, DWORD AuthTargets, DWORD AuthScheme,
    LPCWSTR pwszUserName, LPCWSTR pwszPassword, LPVOID pAuthParams
);

typedef BOOL (*WinHttpSendRequest_t)
(
    HINTERNET hRequest, LPCWSTR lpszHeaders, DWORD dwHeadersLength,
    LPVOID lpOptional, DWORD dwOptionalLength, DWORD dwTotalLength,
    DWORD* dwContext
);

typedef BOOL (*WinHttpReceiveResponse_t)
(
    HINTERNET hRequest, LPVOID lpReserved
);

typedef BOOL (*WinHttpQueryHeaders_t)
(
    HINTERNET hRequest, DWORD dwInfoLevel, LPCWSTR pwszName,
    LPVOID lpBuffer, DWORD* lpdwBufferLength, DWORD* lpdwIndex
);

typedef BOOL (*WinHttpQueryDataAvailable_t)
(
    HINTERNET hRequest, DWORD* lpdwNumberOfBytesAvailable
);

typedef BOOL (*WinHttpReadData_t)
(
    HINTERNET hRequest, LPVOID lpBuffer, DWORD dwNumberOfBytesToRead, 
    DWORD* lpdwNumberOfBytesRead
);

typedef BOOL (*WinHttpCloseHandle_t)
(
    HINTERNET hInternet
);

#endif // WINDOWS_T_H
