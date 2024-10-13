#include "c_types.h"
#include "windows_t.h"
#include "rel_addr.h"
#include "lib_memory.h"
#include "lib_string.h"
#include "hash_api.h"
#include "crypto.h"
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

    LoadLibraryA_t        LoadLibraryA;
    FreeLibrary_t         FreeLibrary;
    ReleaseMutex_t        ReleaseMutex;
    WaitForSingleObject_t WaitForSingleObject;
    CloseHandle_t         CloseHandle;
    Sleep_t               Sleep;

    // protect data
    HMODULE hModule;
    int32   counter;
    HANDLE  hMutex;

    // submodules method
    mt_malloc_t  malloc;
    mt_realloc_t realloc;
    mt_free_t    free;
} WinHTTP;

// methods for user
errno WH_Get(UTF16 url, WinHTTP_Opts* opts, WinHTTP_Resp* resp);
errno WH_Post(UTF16 url, void* body, WinHTTP_Opts* opts, WinHTTP_Resp* resp);

// methods for runtime
bool  WH_Lock();
bool  WH_Unlock();
errno WH_Uninstall();

// hard encoded address in getModulePointer for replacement
#ifdef _WIN64
    #define MODULE_POINTER 0x7FABCDEF111111E2
#elif _WIN32
    #define MODULE_POINTER 0x7FABCDE2
#endif
static WinHTTP* getModulePointer();

static bool wh_lock();
static bool wh_unlock();

static bool initModuleAPI(WinHTTP* module, Context* context);
static bool updateModulePointer(WinHTTP* module);
static bool recoverModulePointer(WinHTTP* module);
static bool initModuleEnvironment(WinHTTP* module, Context* context);
static void eraseModuleMethods(Context* context);

static bool initWinHTTPEnv();
static bool findWinHTTPAPI();
static bool increaseCounter();
static bool decreaseCounter();

WinHTTP_M* InitWinHTTP(Context* context)
{
    // set structure address
    uintptr address = context->MainMemPage;
    uintptr moduleAddr = address + 18000 + RandUintN(address, 128);
    uintptr methodAddr = address + 19000 + RandUintN(address, 128);
    // initialize module
    WinHTTP* module = (WinHTTP*)moduleAddr;
    mem_init(module, sizeof(WinHTTP));
    // store options
    module->NotEraseInstruction = context->NotEraseInstruction;
    errno errno = NO_ERROR;
    for (;;)
    {
        if (!initModuleAPI(module, context))
        {
            errno = ERR_WIN_HTTP_INIT_API;
            break;
        }
        if (!updateModulePointer(module))
        {
            errno = ERR_WIN_HTTP_UPDATE_PTR;
            break;
        }
        if (!initModuleEnvironment(module, context))
        {
            errno = ERR_WIN_HTTP_INIT_ENV;
            break;
        }
        break;
    }
    eraseModuleMethods(context);
    if (errno != NO_ERROR)
    {
        SetLastErrno(errno);
        return NULL;
    }
    // create method set
    WinHTTP_M* method = (WinHTTP_M*)methodAddr;
    method->Get       = GetFuncAddr(&WH_Get);
    method->Post      = GetFuncAddr(&WH_Post);
    method->Lock      = GetFuncAddr(&WH_Lock);
    method->Unlock    = GetFuncAddr(&WH_Unlock);
    method->Uninstall = GetFuncAddr(&WH_Uninstall);
    return method;
}

static bool initModuleAPI(WinHTTP* module, Context* context)
{
    typedef struct { 
        uint hash; uint key; void* proc;
    } winapi;
    winapi list[] =
#ifdef _WIN64
    {
        { 0x92CC6AD999858810, 0x4D23806992FC0259 }, // LoadLibraryA
        { 0x18AF23D87980A16C, 0xE3380ADD44CA22C7 }, // FreeLibrary
    };
#elif _WIN32
    {
        { 0xC4B3F4F2, 0x71C983EF }, // LoadLibraryA
        { 0xBB6DAE22, 0xADCBE537 }, // FreeLibrary
    };
#endif
    for (int i = 0; i < arrlen(list); i++)
    {
        void* proc = FindAPI(list[i].hash, list[i].key);
        if (proc == NULL)
        {
            return false;
        }
        list[i].proc = proc;
    }
    module->LoadLibraryA = list[0].proc;
    module->FreeLibrary  = list[1].proc;

    module->ReleaseMutex        = context->ReleaseMutex;
    module->WaitForSingleObject = context->WaitForSingleObject;
    module->CloseHandle         = context->CloseHandle;
    module->Sleep               = context->Sleep;
    return true;
}

// CANNOT merge updateModulePointer and recoverModulePointer
// to one function with two arguments, otherwise the compiler
// will generate the incorrect instructions.

static bool updateModulePointer(WinHTTP* module)
{
    bool success = false;
    uintptr target = (uintptr)(GetFuncAddr(&getModulePointer));
    for (uintptr i = 0; i < 64; i++)
    {
        uintptr* pointer = (uintptr*)(target);
        if (*pointer != MODULE_POINTER)
        {
            target++;
            continue;
        }
        *pointer = (uintptr)module;
        success = true;
        break;
    }
    return success;
}

static bool recoverModulePointer(WinHTTP* module)
{
    bool success = false;
    uintptr target = (uintptr)(GetFuncAddr(&getModulePointer));
    for (uintptr i = 0; i < 64; i++)
    {
        uintptr* pointer = (uintptr*)(target);
        if (*pointer != (uintptr)module)
        {
            target++;
            continue;
        }
        *pointer = MODULE_POINTER;
        success = true;
        break;
    }
    return success;
}

static bool initModuleEnvironment(WinHTTP* module, Context* context)
{
    // create global mutex
    HANDLE hMutex = context->CreateMutexA(NULL, false, NULL);
    if (hMutex == NULL)
    {
        return false;
    }
    module->hMutex = hMutex;
    // copy submodule methods
    module->malloc  = context->mt_malloc;
    module->realloc = context->mt_realloc;
    module->free    = context->mt_free;
    return true;
}

static void eraseModuleMethods(Context* context)
{
    if (context->NotEraseInstruction)
    {
        return;
    }
    uintptr begin = (uintptr)(GetFuncAddr(&initModuleAPI));
    uintptr end   = (uintptr)(GetFuncAddr(&eraseModuleMethods));
    uintptr size  = end - begin;
    RandBuffer((byte*)begin, (int64)size);
}

// updateModulePointer will replace hard encode address to the actual address.
// Must disable compiler optimize, otherwise updateModulePointer will fail.
#pragma optimize("", off)
static WinHTTP* getModulePointer()
{
    uintptr pointer = MODULE_POINTER;
    return (WinHTTP*)(pointer);
}
#pragma optimize("", on)

__declspec(noinline)
static bool wh_lock()
{
    WinHTTP* module = getModulePointer();

    DWORD event = module->WaitForSingleObject(module->hMutex, INFINITE);
    return (event == WAIT_OBJECT_0 || event == WAIT_ABANDONED);
}

__declspec(noinline)
static bool wh_unlock()
{
    WinHTTP* module = getModulePointer();

    return module->ReleaseMutex(module->hMutex);
}

static bool initWinHTTPEnv()
{
    WinHTTP* module = getModulePointer();

    if (!wh_lock())
    {
        return false;
    }

    bool success = false;
    for (;;)
    {
        if (module->hModule != NULL)
        {
            success = true;
            break;
        }
        // decrypt to "winhttp.dll"
        byte dllName[] = {
            'w'^0xAC, 'i'^0x1F, 'n'^0x49, 'h'^0xC6, 
            't'^0xAC, 't'^0x1F, 'p'^0x49, '.'^0xC6, 
            'd'^0xAC, 'l'^0x1F, 'l'^0x49, 000^0xC6,
        };
        byte key[] = {0xAC, 0x1F, 0x49, 0xC6};
        XORBuf(dllName, sizeof(dllName), key, sizeof(key));
        // load winhttp.dll
        HMODULE hModule = module->LoadLibraryA(dllName);
        if (hModule == NULL)
        {
            break;
        }
        // prepare API address
        if (!findWinHTTPAPI())
        {
            module->FreeLibrary(hModule);
            break;
        }
        module->hModule = hModule;
        success = true;
        break;
    }

    if (!wh_unlock())
    {
        return false;
    }
    return success;
}

static bool findWinHTTPAPI()
{
    WinHTTP* module = getModulePointer();

    typedef struct { 
        uint hash; uint key; void* proc;
    } winapi;
    winapi list[] =
#ifdef _WIN64
    {
        { 0xEC3F06518D55B0C7, 0x0706C192EB0BF16E }, // WinHttpCrackUrl
        { 0x5029A572232B4141, 0x6ED6F8304F6E818F }, // WinHttpOpen
        { 0xD1329B7029BBB9AE, 0x34A46B22BB2E9DD9 }, // WinHttpConnect
        { 0xB52D706DDFB69F24, 0xFAFDABC91A9EF4E8 }, // WinHttpOpenRequest
        { 0xBD8A60F53EAB080D, 0xD594CC87C67311C8 }, // WinHttpSendRequest
        { 0xABA74353B61115E5, 0xAE6EF6D3F07F50A7 }, // WinHttpReceiveResponse
        { 0xB4DEE83E6F30EE22, 0xD15DF5DAA1F5C82B }, // WinHttpQueryDataAvailable
        { 0x8222A4742A82B293, 0x7033455E4998396E }, // WinHttpReadData
        { 0x40949660847FA663, 0x27F73DB59BBAD437 }, // WinHttpCloseHandle
    };
#elif _WIN32
    {
        { 0x39CD8BBF, 0x0343789D }, // WinHttpCrackUrl
        { 0x1B1A608A, 0xD4DB3A21 }, // WinHttpOpen
        { 0x3AA6FEC9, 0xF63606EE }, // WinHttpConnect
        { 0xB8414830, 0x4896A05B }, // WinHttpOpenRequest
        { 0x8E57BC99, 0x46690252 }, // WinHttpSendRequest
        { 0x9B938432, 0x876406EC }, // WinHttpReceiveResponse
        { 0xCF231202, 0x4558CCF5 }, // WinHttpQueryDataAvailable
        { 0xCB96057E, 0xE272676B }, // WinHttpReadData
        { 0xF87CC6CD, 0x1CDF2720 }, // WinHttpCloseHandle
    };
#endif
    for (int i = 0; i < arrlen(list); i++)
    {
        void* proc = FindAPI(list[i].hash, list[i].key);
        if (proc == NULL)
        {
            return false;
        }
        list[i].proc = proc;
    }
    module->WinHttpCrackUrl           = list[0x00].proc;
    module->WinHttpOpen               = list[0x01].proc;
    module->WinHttpConnect            = list[0x02].proc;
    module->WinHttpOpenRequest        = list[0x03].proc;
    module->WinHttpSendRequest        = list[0x04].proc;
    module->WinHttpReceiveResponse    = list[0x05].proc;
    module->WinHttpQueryDataAvailable = list[0x06].proc;
    module->WinHttpReadData           = list[0x07].proc;
    module->WinHttpCloseHandle        = list[0x08].proc;
    return true;
}

static bool increaseCounter()
{
    WinHTTP* module = getModulePointer();

    if (!wh_lock())
    {
        return false;
    }
    module->counter++;
    // prevent unexpected status
    if (module->counter < 1)
    {
        module->counter = 1;
    }
    if (!wh_unlock())
    {
        return false;
    }
    return true;
}

static bool decreaseCounter()
{
    WinHTTP* module = getModulePointer();

    if (!wh_lock())
    {
        return false;
    }
    module->counter--;
    // prevent unexpected status
    if (module->counter < 0)
    {
        module->counter = 0;
    }
    if (!wh_unlock())
    {
        return false;
    }
    return true;
}

__declspec(noinline)
errno WH_Get(UTF16 url, WinHTTP_Opts* opts, WinHTTP_Resp* resp)
{
    WinHTTP* module = getModulePointer();

    if (!initWinHTTPEnv())
    {
        return GetLastErrno();
    }
    if (!increaseCounter())
    {
        return GetLastErrno();
    }

    if (opts == NULL)
    {
        WinHTTP_Opts opt = {
            .UserAgent   = NULL,
            .ContentType = NULL,
            .Headers     = NULL,
            .Proxy       = NULL,
            .Timeout     = 15*1000,
            .AccessType  = WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
        };
        opts = &opt;
    }

    // parse input URL
    uint16 scheme[16];
    uint16 hostname[256];
    uint16 username[256];
    uint16 password[256];
    uint16 path[1024];
    uint16 extra[2048];

    mem_init(scheme, sizeof(scheme));
    mem_init(hostname, sizeof(hostname));
    mem_init(username, sizeof(username));
    mem_init(password, sizeof(password));
    mem_init(path, sizeof(path));
    mem_init(extra, sizeof(extra));

    URL_COMPONENTS url_com;
    mem_init(&url_com, sizeof(url_com));
    url_com.dwStructSize      = sizeof(url_com);
    url_com.lpszScheme        = scheme;
    url_com.dwSchemeLength    = arrlen(scheme);
    url_com.lpszHostName      = hostname;
    url_com.dwHostNameLength  = arrlen(hostname);
    url_com.lpszUserName      = username;
    url_com.dwUserNameLength  = arrlen(username);
    url_com.lpszPassword      = password;
    url_com.dwPasswordLength  = arrlen(password);
    url_com.lpszUrlPath       = path;
    url_com.dwUrlPathLength   = arrlen(path);
    url_com.lpszExtraInfo     = extra;
    url_com.dwExtraInfoLength = arrlen(extra);

    HINTERNET hSession = NULL;
    HINTERNET hConnect = NULL;
    HINTERNET hRequest = NULL;

    bool success = false;
    for (;;)
    {
        // split input url
        if (!module->WinHttpCrackUrl(url, 0, 0, &url_com))
        {
            break;
        }
        dbg_log("[WinHTTP]", "Get %ls", url);
        switch (url_com.nScheme)
        {
        case INTERNET_SCHEME_HTTP:
            break;
        case INTERNET_SCHEME_HTTPS:
            break;
        default:
            goto exit_loop;
        }

        // create session
        hSession = module->WinHttpOpen(
            opts->UserAgent, opts->AccessType, NULL, NULL, 0
        );
        if (hSession == NULL)
        {
            break;
        }
        // create connection
        hConnect = module->WinHttpConnect(
            hSession, hostname, url_com.nPort, 0
        );
        if (hConnect == NULL)
        {
            break;
        }
        // create request
        uint16 reqPath[arrlen(path) + arrlen(extra)];
        mem_init(reqPath, sizeof(reqPath));
        strcpy_w(reqPath, path);
        strcpy_w(reqPath + url_com.dwUrlPathLength, extra);
        DWORD flags = 0;
        if (url_com.nScheme == INTERNET_SCHEME_HTTPS)
        {
            flags = WINHTTP_FLAG_SECURE;
        }
        hRequest = module->WinHttpOpenRequest(
            hConnect, L"GET", reqPath, NULL, 
            WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, flags
        );
        if (hRequest == NULL)
        {
            break;
        }
        // send request
        bool ok = module->WinHttpSendRequest(
            hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
            WINHTTP_NO_REQUEST_DATA, 0, 0, NULL
        );
        if (!ok)
        {
            break;
        }
        // receive response
        if (!module->WinHttpReceiveResponse(hRequest, NULL))
        {
            break;
        }
        // read data
        byte* buf = NULL;
        uint  len = 0;
        for (;;)
        {
            DWORD size;
            if (!module->WinHttpQueryDataAvailable(hRequest, &size))
            {
                goto exit_loop;
            }
            if (size == 0)
            {
                break;
            }
            // record current offset
            uint off = len;
            // allocate buffer
            len += (uint)size;
            buf = module->realloc(buf, len);
            if (buf == NULL)
            {
                goto exit_loop;
            }
            if (!module->WinHttpReadData(hRequest, buf + off, size, &size))
            {
                goto exit_loop;
            }
        }
        // TODO
        // resp->StatusCode = 200; 
        // resp->Headers    = NULL;
        resp->BodyBuf  = buf;
        resp->BodySize = (uint64)len;
        success = true;
        break;
    }
exit_loop:

    errno errno = NO_ERROR;
    if (!success)
    {
        errno = GetLastErrno();
    }

    if (hRequest != NULL)
    {
        if (!module->WinHttpCloseHandle(hRequest) && errno == NO_ERROR)
        {
            errno = GetLastErrno();
        }
    }
    if (hConnect != NULL)
    {
        if (!module->WinHttpCloseHandle(hConnect) && errno == NO_ERROR)
        {
            errno = GetLastErrno();
        }
    }
    if (hSession != NULL)
    {
        if (!module->WinHttpCloseHandle(hSession) && errno == NO_ERROR)
        {
            errno = GetLastErrno();
        }
    }

    if (!decreaseCounter())
    {
        return GetLastErrno();
    }
    return errno;
}

__declspec(noinline)
errno WH_Post(UTF16 url, void* body, WinHTTP_Opts* opts, WinHTTP_Resp* resp)
{
    WinHTTP* module = getModulePointer();

    if (!initWinHTTPEnv())
    {
        return GetLastErrno();
    }
    if (!increaseCounter())
    {
        return GetLastErrno();
    }

    for (;;)
    {
        break;
    }

    if (!decreaseCounter())
    {
        return GetLastErrno();
    }
    return NO_ERROR;
}

__declspec(noinline)
bool WH_Lock()
{
    WinHTTP* module = getModulePointer();

    // maximum sleep 10s 
    for (int i = 0; i < 1000; i++)
    {
        if (!wh_lock())
        {
            return false;
        }
        if (module->counter < 1)
        {
            return true;
        }
        if (!wh_unlock())
        {
            return false;
        }
        module->Sleep(10);
    }

    // if timeout, reset counter
    if (!wh_lock())
    {
        return false;
    }
    module->counter = 0;
    return true;
}

__declspec(noinline)
bool WH_Unlock()
{
    return wh_unlock();
}

__declspec(noinline)
errno WH_Uninstall()
{
    WinHTTP* module = getModulePointer();

    errno errno = NO_ERROR;

    // free winhttp.dll
    if (module->hModule != NULL)
    {
        if (!module->FreeLibrary(module->hModule) && errno == NO_ERROR)
        {
            errno = ERR_WIN_HTTP_FREE_LIBRARY;
        }
    }

    // close mutex
    if (!module->CloseHandle(module->hMutex) && errno == NO_ERROR)
    {
        errno = ERR_WIN_HTTP_CLOSE_MUTEX;
    }

    // recover instructions
    if (module->NotEraseInstruction)
    {
        if (!recoverModulePointer(module) && errno == NO_ERROR)
        {
            errno = ERR_WIN_HTTP_RECOVER_INST;
        }
    }
    return errno;
}
