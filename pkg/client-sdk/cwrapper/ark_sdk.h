#ifndef ARK_SDK_H
#define ARK_SDK_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef uintptr_t ArkClientHandle;
typedef uintptr_t ContextHandle;

typedef struct {
    char* to;
    uint64_t amount;
} Receiver;

#define ARK_SDK_SUCCESS                  0
#define ARK_SDK_ERROR_INVALID_HANDLE     -1
#define ARK_SDK_ERROR_INITIALIZATION     -2
#define ARK_SDK_ERROR_UNLOCK_FAILED      -3
#define ARK_SDK_ERROR_NULL_POINTER       -4
#define ARK_SDK_ERROR_OPERATION_FAILED   -5
#define ARK_SDK_ERROR_MEMORY_ALLOCATION  -6
#define ARK_SDK_ERROR_INVALID_ARGUMENT   -7
#define ARK_SDK_ERROR_LOCK_FAILED        -8
#define ARK_SDK_ERROR_RECEIVE_FAILED     -9
#define ARK_SDK_ERROR_BALANCE_FAILED     -10
#define ARK_SDK_ERROR_SEND_FAILED        -11
#define ARK_SDK_ERROR_CLAIM_FAILED       -12
#define ARK_SDK_ERROR_REDEEM_FAILED      -13
#define ARK_SDK_ERROR_DUMP_FAILED        -14
#define ARK_SDK_ERROR_LIST_VTXOS_FAILED  -15
#define ARK_SDK_ERROR_HISTORY_FAILED     -16
#define ARK_SDK_ERROR_CONFIG_FAILED      -17

ArkClientHandle ArkClientNew(char** errorMsg);
int DestroyArkClient(ArkClientHandle handle);
int ArkClientInit(ArkClientHandle handle, ContextHandle ctxHandle, char* aspUrl, char* password, char** errorMsg);
int ArkClientUnlock(ArkClientHandle handle, ContextHandle ctxHandle, char* password, char** errorMsg);
int ArkClientReceive(ArkClientHandle handle, ContextHandle ctxHandle, char** offchainAddr, char** boardingAddr, char** errorMsg);
int ArkClientBalance(ArkClientHandle handle, ContextHandle ctxHandle, int computeExpiryDetails, char** balance, char** errorMsg);
int ArkClientSendAsync(ArkClientHandle handle, ContextHandle ctxHandle, int withExpiryCoinselect, Receiver* receivers, int receiversCount, char** txid, char** errorMsg);
int ArkClientClaim(ArkClientHandle handle, ContextHandle ctxHandle, char** txid, char** errorMsg);

ContextHandle CreateContext();
int DestroyContext(ContextHandle handle);
void FreeString(char* str);

#ifdef __cplusplus
}
#endif

#endif // ARK_SDK_H
