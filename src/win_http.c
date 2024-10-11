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
    bool   isLoad;
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

}

static bool initModuleAPI(WinHTTP* module, Context* context)
{
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
        { 0x92CC6AD999858810, 0x4D23806992FC0259 }, // LoadLibraryA
        { 0x18AF23D87980A16C, 0xE3380ADD44CA22C7 }, // FreeLibrary
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
    module->WinHttpCrackUrl           = list[0x00].proc;
    module->WinHttpOpen               = list[0x01].proc;
    module->WinHttpConnect            = list[0x02].proc;
    module->WinHttpOpenRequest        = list[0x03].proc;
    module->WinHttpSendRequest        = list[0x04].proc;
    module->WinHttpReceiveResponse    = list[0x05].proc;
    module->WinHttpQueryDataAvailable = list[0x06].proc;
    module->WinHttpReadData           = list[0x07].proc;
    module->WinHttpCloseHandle        = list[0x08].proc;
    module->LoadLibraryA              = list[0x09].proc;
    module->FreeLibrary               = list[0x0A].proc;

    module->CloseHandle = context->CloseHandle;
    return true;
}

static bool updateModulePointer(WinHTTP* module)
{

}

static bool recoverModulePointer(WinHTTP* module)
{

}

static bool initModuleEnvironment(WinHTTP* module, Context* context)
{

}

static void eraseModuleMethods(Context* context)
{

}
