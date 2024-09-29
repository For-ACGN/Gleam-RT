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

#define ERR_RUNTIME_INIT_DEBUGGER       (0x01000001)
#define ERR_RUNTIME_INVALID_ARGS_STUB   (0x01000002)
#define ERR_RUNTIME_ALLOC_MEMORY        (0x01000003)
#define ERR_RUNTIME_INIT_API            (0x01000004)
#define ERR_RUNTIME_ADJUST_PROTECT      (0x01000005)
#define ERR_RUNTIME_RECOVER_PROTECT     (0x01000006)
#define ERR_RUNTIME_UPDATE_PTR          (0x01000007)
#define ERR_RUNTIME_INIT_IAT_HOOKS      (0x01000008)
#define ERR_RUNTIME_FLUSH_INST          (0x01000009)
#define ERR_RUNTIME_START_EVENT_HANDLER (0x0100000A)

#define ERR_RUNTIME_CREATE_GLOBAL_MUTEX (0x0100011)
#define ERR_RUNTIME_CREATE_SLEEP_MUTEX  (0x0100012)
#define ERR_RUNTIME_CREATE_EVENT_ARRIVE (0x0100013)
#define ERR_RUNTIME_CREATE_EVENT_DONE   (0x0100014)
#define ERR_RUNTIME_CREATE_EVENT_MUTEX  (0x0100015)

#define ERR_RUNTIME_LOCK            (0x01000201)
#define ERR_RUNTIME_UNLOCK          (0x01000202)
#define ERR_RUNTIME_LOCK_LIBRARY    (0x01000203)
#define ERR_RUNTIME_LOCK_MEMORY     (0x01000204)
#define ERR_RUNTIME_LOCK_THREAD     (0x01000205)
#define ERR_RUNTIME_LOCK_RESOURCE   (0x01000206)
#define ERR_RUNTIME_LOCK_ARGUMENT   (0x01000207)
#define ERR_RUNTIME_UNLOCK_LIBRARY  (0x01000208)
#define ERR_RUNTIME_UNLOCK_MEMORY   (0x01000209)
#define ERR_RUNTIME_UNLOCK_THREAD   (0x0100020A)
#define ERR_RUNTIME_UNLOCK_RESOURCE (0x0100020B)
#define ERR_RUNTIME_UNLOCK_ARGUMENT (0x0100020C)

#define ERR_RUNTIME_LOCK_SLEEP           (0x01000301)
#define ERR_RUNTIME_UNLOCK_SLEEP         (0x01000302)
#define ERR_RUNTIME_LOCK_EVENT           (0x01000303)
#define ERR_RUNTIME_UNLOCK_EVENT         (0x01000304)
#define ERR_RUNTIME_NOTICE_EVENT_HANDLER (0x01000305)
#define ERR_RUNTIME_WAIT_EVENT_HANDLER   (0x01000306)
#define ERR_RUNTIME_RESET_EVENT          (0x01000307)

#define ERR_RUNTIME_CREATE_WAITABLE_TIMER (0x01000401)
#define ERR_RUNTIME_SET_WAITABLE_TIMER    (0x01000402)
#define ERR_RUNTIME_DEFENSE_RT            (0x01000403)
#define ERR_RUNTIME_FLUSH_INST_CACHE      (0x01000404)
#define ERR_RUNTIME_CLOSE_WAITABLE_TIMER  (0x01000405)

#define ERR_RUNTIME_EXIT_EVENT_HANDLER    (0x0100FF01)
#define ERR_RUNTIME_CLEAN_H_MUTEX         (0x0100FF02)
#define ERR_RUNTIME_CLEAN_H_TIMER         (0x0100FF03)
#define ERR_RUNTIME_CLEAN_H_MUTEX_SLEEP   (0x0100FF04)
#define ERR_RUNTIME_CLEAN_H_EVENT_ARRIVE  (0x0100FF05)
#define ERR_RUNTIME_CLEAN_H_EVENT_DONE    (0x0100FF06)
#define ERR_RUNTIME_CLEAN_H_MUTEX_EVENT   (0x0100FF07)
#define ERR_RUNTIME_CLEAN_H_EVENT_HANDLER (0x0100FF08)
#define ERR_RUNTIME_CLEAN_FREE_MEM        (0x0100FF09)
#define ERR_RUNTIME_EXIT_RECOVER_INST     (0x0100FF0A)

#define ERR_LIBRARY_INIT_API      (0x02000001)
#define ERR_LIBRARY_UPDATE_PTR    (0x02000002)
#define ERR_LIBRARY_INIT_ENV      (0x02000003)
#define ERR_LIBRARY_CLEAN_MODULE  (0x0200FF01|ERR_FLAG_CAN_IGNORE)
#define ERR_LIBRARY_DELETE_MODULE (0x0200FF02|ERR_FLAG_CAN_IGNORE)
#define ERR_LIBRARY_FREE_LIST     (0x0200FF03|ERR_FLAG_CAN_IGNORE)
#define ERR_LIBRARY_CLOSE_MUTEX   (0x0200FF04|ERR_FLAG_CAN_IGNORE)
#define ERR_LIBRARY_RECOVER_INST  (0x0200FF05|ERR_FLAG_CAN_IGNORE)

#define ERR_MEMORY_INIT_API         (0x03000001)
#define ERR_MEMORY_UPDATE_PTR       (0x03000002)
#define ERR_MEMORY_INIT_ENV         (0x03000003)
#define ERR_MEMORY_ENCRYPT_PAGE     (0x03000004)
#define ERR_MEMORY_DECRYPT_PAGE     (0x03000005)
#define ERR_MEMORY_CLEAN_PAGE       (0x0300FF01|ERR_FLAG_CAN_IGNORE)
#define ERR_MEMORY_CLEAN_REGION     (0x0300FF02|ERR_FLAG_CAN_IGNORE)
#define ERR_MEMORY_DELETE_PAGE      (0x0300FF03|ERR_FLAG_CAN_IGNORE)
#define ERR_MEMORY_DELETE_REGION    (0x0300FF04|ERR_FLAG_CAN_IGNORE)
#define ERR_MEMORY_FREE_PAGE_LIST   (0x0300FF05|ERR_FLAG_CAN_IGNORE)
#define ERR_MEMORY_FREE_REGION_LIST (0x0300FF06|ERR_FLAG_CAN_IGNORE)
#define ERR_MEMORY_CLOSE_MUTEX      (0x0300FF07|ERR_FLAG_CAN_IGNORE)
#define ERR_MEMORY_RECOVER_INST     (0x0300FF08|ERR_FLAG_CAN_IGNORE)

#define ERR_THREAD_INIT_API        (0x04000001)
#define ERR_THREAD_UPDATE_PTR      (0x04000002)
#define ERR_THREAD_INIT_ENV        (0x04000003)
#define ERR_THREAD_GET_CURRENT_TID (0x04000004)
#define ERR_THREAD_SUSPEND         (0x04000005|ERR_FLAG_CAN_IGNORE)
#define ERR_THREAD_RESUME          (0x04000006|ERR_FLAG_CAN_IGNORE)
#define ERR_THREAD_TERMINATE       (0x04000007|ERR_FLAG_CAN_IGNORE)
#define ERR_THREAD_WAIT_TERMINATE  (0x04000008|ERR_FLAG_CAN_IGNORE)
#define ERR_THREAD_DELETE_THREAD   (0x04000101|ERR_FLAG_CAN_IGNORE)
#define ERR_THREAD_CLOSE_HANDLE    (0x0400FF01|ERR_FLAG_CAN_IGNORE)
#define ERR_THREAD_FREE_LIST       (0x0400FF02|ERR_FLAG_CAN_IGNORE)
#define ERR_THREAD_CLOSE_MUTEX     (0x0400FF03|ERR_FLAG_CAN_IGNORE)
#define ERR_THREAD_RECOVER_INST    (0x0400FF04|ERR_FLAG_CAN_IGNORE)

#define ERR_RESOURCE_INIT_API         (0x05000001)
#define ERR_RESOURCE_UPDATE_PTR       (0x05000002)
#define ERR_RESOURCE_INIT_ENV         (0x05000003)
#define ERR_RESOURCE_CLOSE_HANDLE     (0x0500FF01|ERR_FLAG_CAN_IGNORE)
#define ERR_RESOURCE_FIND_CLOSE       (0x0500FF02|ERR_FLAG_CAN_IGNORE)
#define ERR_RESOURCE_INVALID_SRC_TYPE (0x0500FF03|ERR_FLAG_CAN_IGNORE)
#define ERR_RESOURCE_FREE_HANDLE_LIST (0x0500FF04|ERR_FLAG_CAN_IGNORE)
#define ERR_RESOURCE_WSA_CLEANUP      (0x0500FF05|ERR_FLAG_CAN_IGNORE)
#define ERR_RESOURCE_CLOSE_MUTEX      (0x0500FF06|ERR_FLAG_CAN_IGNORE)
#define ERR_RESOURCE_RECOVER_INST     (0x0500FF07|ERR_FLAG_CAN_IGNORE)

#define ERR_ARGUMENT_INIT_API     (0x06000001)
#define ERR_ARGUMENT_UPDATE_PTR   (0x06000002)
#define ERR_ARGUMENT_INIT_ENV     (0x06000003)
#define ERR_ARGUMENT_ALLOC_MEM    (0x06000004)
#define ERR_ARGUMENT_FREE_MEM     (0x0600FF01|ERR_FLAG_CAN_IGNORE)
#define ERR_ARGUMENT_CLOSE_MUTEX  (0x0600FF02|ERR_FLAG_CAN_IGNORE)
#define ERR_ARGUMENT_RECOVER_INST (0x0600FF03|ERR_FLAG_CAN_IGNORE)

#endif // ERRNO_H
