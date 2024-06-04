#include "c_types.h"
#include "errno.h"

void SetLastErrno(errno err)
{
#ifdef _WIN64
    uintptr teb = __readgsqword(0x30);
    errno*  ptr = (errno*)(teb + 0x68);
#elif _WIN32
    uintptr teb = __readfsdword(0x18);
    errno*  ptr = (errno*)(teb + 0x34);
#endif
    *ptr = err;
}

errno GetLastErrno()
{
#ifdef _WIN64
    uintptr teb = __readgsqword(0x30);
    errno*  ptr = (errno*)(teb + 0x68);
#elif _WIN32
    uintptr teb = __readfsdword(0x18);
    errno*  ptr = (errno*)(teb + 0x34);
#endif
    return *ptr;
}
