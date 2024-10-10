#include "c_types.h"
#include "windows_t.h"
#include "rel_addr.h"
#include "lib_memory.h"
#include "lib_string.h"
#include "hash_api.h"
#include "context.h"
#include "random.h"
#include "errno.h"
#include "win_http.h"
#include "debug.h"

#ifdef RELEASE_MODE
    #define CHUNK_SIZE 4096
#else
    #define CHUNK_SIZE 4
#endif

typedef struct {
    // store options
    bool NotEraseInstruction;

    // API addresses
    WinHttpCrackUrl_t           WinHttpCrackUrl;
    WinHttpOpen_t               WinHttpOpen;
    WinHttpConnect_t            WinHttpConnect;
    WinHttpOpenRequest_t        WinHttpOpenRequest;
    WinHttpSendRequest_t        WinHttpSendRequest;
    WinHttpReceiveResponse_t    WinHttpReceiveResponse;
    WinHttpQueryDataAvailable_t WinHttpQueryDataAvailable;
    WinHttpReadData_t           WinHttpReadData;
    WinHttpCloseHandle_t        WinHttpCloseHandle;

    LoadLibraryA_t LoadLibraryA;
    FreeLibrary_t  FreeLibrary;
    CloseHandle_t  CloseHandle;

    // protect data
    int32  counter;
    HANDLE hMutex;

    // submodules method
    malloc_t  malloc;
    mt_free_t free;
} WinHTTP;

// methods for user
errno WH_Get(UTF16 url, WinHTTP_Opts* opts, WinHTTP_Resp* resp);
errno WH_Post(UTF16 url, void* body, WinHTTP_Opts* opts, WinHTTP_Resp* resp);

// methods for runtime
errno WH_Lock();
errno WH_Unlock();
errno WH_Uninstall();

// hard encoded address in getModulePointer for replacement
#ifdef _WIN64
    #define MODULE_POINTER 0x7FABCDEF111111E2
#elif _WIN32
    #define MODULE_POINTER 0x7FABCDE2
#endif
static WinHTTP* getModulePointer();

static bool initModuleAPI(WinHTTP* module, Context* context);
static bool updateModulePointer(WinHTTP* module);
static bool recoverModulePointer(WinHTTP* module);
static bool initModuleEnvironment(WinHTTP* module, Context* context);
static void eraseModuleMethods(Context* context);

WinHTTP_M* InitWinHTTP(Context* context)
{

}
