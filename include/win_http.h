#ifndef WIN_HTTP_H
#define WIN_HTTP_H

#include "c_types.h"
#include "lib_string.h"
#include "context.h"
#include "errno.h"

typedef struct {
    UTF16  UserAgent;   // default User-Agent
    UTF16  ContentType; // for POST method
    UTF16  Headers;     // split by "\r\n"
    UTF16  Proxy;       // http://user:pass@host.com/
    uint32 Timeout;     // millseconds
} WinHTTP_Opts;

typedef struct {
    int32 StatusCode;
    UTF16 Headers;
    void* Body;
} WinHTTP_Resp;

typedef errno (*WHGet_t)
(
    UTF16 url, WinHTTP_Opts* opts, WinHTTP_Resp* resp
);

typedef errno (*WHPost_t)
(
    UTF16 url, void* body, WinHTTP_Opts* opts, WinHTTP_Resp* resp
);

typedef errno (*WHLock_t)();
typedef errno (*WHUnlock_t)();
typedef errno (*WHUninstall_t)();

typedef struct {
    WHGet_t  Get;
    WHPost_t Post;

    WHLock_t      Lock;
    WHUnlock_t    Unlock;
    WHUninstall_t Uninstall;
} WinHTTP_M;

WinHTTP_M* InitWinHTTP(Context* context);

#endif // WIN_HTTP_H
