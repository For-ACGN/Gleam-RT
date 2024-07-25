#ifndef ERRNO_H
#define ERRNO_H

#include "c_types.h"

typedef uint32 errno;

void  SetLastErrno(errno errno);
errno GetLastErrno();

// 00，，，，，， module id
// ，，00，，，， error flags
// ，，，，00，， major error id
// ，，，，，，00 minor error id

#define NO_ERROR 0x00000000

#define ERR_FLAG_CAN_IGNORE 0x00010000

#define ERR_RUNTIME_INIT_DEBUG_MODULE   (0x01000001)
#define ERR_RUNTIME_ALLOC_MEMORY        (0x01000002)
#define ERR_RUNTIME_INIT_API            (0x01000003)
#define ERR_RUNTIME_ADJUST_PROTECT      (0x01000004)
#define ERR_RUNTIME_UPDATE_PTR          (0x01000005)
#define ERR_RUNTIME_INIT_IAT_HOOKS      (0x01000006)
#define ERR_RUNTIME_FLUSH_INST          (0x01000007)
#define ERR_RUNTIME_START_TRIGGER       (0x01000008)
#define ERR_RUNTIME_DUP_PROCESS_HANDLE  (0x01000101)
#define ERR_RUNTIME_CREATE_GLOBAL_MUTEX (0x01000102)
#define ERR_RUNTIME_CREATE_SLEEP_MUTEX  (0x01000103)
#define ERR_RUNTIME_CREATE_EVENT_ARRIVE (0x01000104)
#define ERR_RUNTIME_CREATE_EVENT_DONE   (0x01000105)
#define ERR_RUNTIME_CREATE_EVENT_MUTEX  (0x01000106)
#define ERR_RUNTIME_LOCK                (0x01000201)
#define ERR_RUNTIME_UNLOCK              (0x01000202)
#define ERR_RUNTIME_LOCK_LIBRARY        (0x01000203)
#define ERR_RUNTIME_LOCK_MEMORY         (0x01000204)
#define ERR_RUNTIME_LOCK_THREAD         (0x01000205)
#define ERR_RUNTIME_LOCK_RESOURCE       (0x01000206)
#define ERR_RUNTIME_UNLOCK_LIBRARY      (0x01000207)
#define ERR_RUNTIME_UNLOCK_MEMORY       (0x01000208)
#define ERR_RUNTIME_UNLOCK_THREAD       (0x01000209)
#define ERR_RUNTIME_UNLOCK_RESOURCE     (0x0100020A)
#define ERR_RUNTIME_LOCK_SLEEP          (0x0100020B)
#define ERR_RUNTIME_UNLOCK_SLEEP        (0x0100020C)
#define ERR_RUNTIME_LOCK_EVENT          (0x0100020D)
#define ERR_RUNTIME_UNLOCK_EVENT        (0x0100020E)
#define ERR_RUNTIME_NOTICE_TRIGGER      (0x0100020F)
#define ERR_RUNTIME_WAIT_TRIGGER        (0x01000210)
#define ERR_RUNTIME_RESET_EVENT         (0x01000211)
#define ERR_RUNTIME_DEFENSE_RT          (0x01000212)
#define ERR_RUNTIME_FLUSH_INST_CACHE    (0x01000213)

#define ERR_LIBRARY_INIT_API     (0x02000001)
#define ERR_LIBRARY_UPDATE_PTR   (0x02000002)
#define ERR_LIBRARY_INIT_ENV     (0x02000003)
#define ERR_LIBRARY_CLEAN_MODULE (0x0200FF01|ERR_FLAG_CAN_IGNORE)
#define ERR_LIBRARY_FREE_LIST    (0x0200FF02|ERR_FLAG_CAN_IGNORE)
#define ERR_LIBRARY_CLOSE_MUTEX  (0x0200FF03|ERR_FLAG_CAN_IGNORE)

#define ERR_MEMORY_INIT_API         (0x03000001)
#define ERR_MEMORY_UPDATE_PTR       (0x03000002)
#define ERR_MEMORY_INIT_ENV         (0x03000003)
#define ERR_MEMORY_ENCRYPT_PAGE     (0x03000004)
#define ERR_MEMORY_DECRYPT_PAGE     (0x03000005)
#define ERR_MEMORY_CLEAN_PAGE       (0x0300FF01|ERR_FLAG_CAN_IGNORE)
#define ERR_MEMORY_CLEAN_REGION     (0x0300FF02|ERR_FLAG_CAN_IGNORE)
#define ERR_MEMORY_FREE_PAGE_LIST   (0x0300FF03|ERR_FLAG_CAN_IGNORE)
#define ERR_MEMORY_FREE_REGION_LIST (0x0300FF04|ERR_FLAG_CAN_IGNORE)
#define ERR_MEMORY_CLOSE_MUTEX      (0x0300FF05|ERR_FLAG_CAN_IGNORE)

#define ERR_THREAD_INIT_API        (0x04000001)
#define ERR_THREAD_UPDATE_PTR      (0x04000002)
#define ERR_THREAD_INIT_ENV        (0x04000003)
#define ERR_THREAD_GET_CURRENT_TID (0x04000004)
#define ERR_THREAD_SUSPEND         (0x04000005|ERR_FLAG_CAN_IGNORE)
#define ERR_THREAD_RESUME          (0x04000006|ERR_FLAG_CAN_IGNORE)
#define ERR_THREAD_TERMINATE       (0x04000007|ERR_FLAG_CAN_IGNORE)
#define ERR_THREAD_CLOSE_HANDLE    (0x0400FF01|ERR_FLAG_CAN_IGNORE)
#define ERR_THREAD_FREE_LIST       (0x0400FF02|ERR_FLAG_CAN_IGNORE)
#define ERR_THREAD_CLOSE_MUTEX     (0x0400FF03|ERR_FLAG_CAN_IGNORE)

#define ERR_RESOURCE_INIT_API         (0x05000001)
#define ERR_RESOURCE_UPDATE_PTR       (0x05000002)
#define ERR_RESOURCE_INIT_ENV         (0x05000003)
#define ERR_RESOURCE_CLOSE_HANDLE     (0x0500FF01|ERR_FLAG_CAN_IGNORE)
#define ERR_RESOURCE_FIND_CLOSE       (0x0500FF02|ERR_FLAG_CAN_IGNORE)
#define ERR_RESOURCE_INVALID_SRC_TYPE (0x0500FF03|ERR_FLAG_CAN_IGNORE)
#define ERR_RESOURCE_FREE_HANDLE_LIST (0x0500FF04|ERR_FLAG_CAN_IGNORE)
#define ERR_RESOURCE_WSA_CLEANUP      (0x0500FF05|ERR_FLAG_CAN_IGNORE)
#define ERR_RESOURCE_CLOSE_MUTEX      (0x0500FF06|ERR_FLAG_CAN_IGNORE)

#define ERR_ARGUMENT_INIT_API    (0x06000001)
#define ERR_ARGUMENT_UPDATE_PTR  (0x06000002)
#define ERR_ARGUMENT_INIT_ENV    (0x06000003)
#define ERR_ARGUMENT_ALLOC_MEM   (0x06000004)
#define ERR_ARGUMENT_FREE_MEM    (0x0600FF01|ERR_FLAG_CAN_IGNORE)
#define ERR_ARGUMENT_CLOSE_MUTEX (0x0600FF02|ERR_FLAG_CAN_IGNORE)

#endif // ERRNO_H
