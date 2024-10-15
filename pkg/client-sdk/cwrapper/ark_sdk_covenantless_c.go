package main

/*
#include <stdlib.h>
#include <stdint.h>

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
*/
import "C"
import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"unsafe"

	arksdk "github.com/ark-network/ark/pkg/client-sdk"
	inmemorystore "github.com/ark-network/ark/pkg/client-sdk/store/inmemory"
)

var (
	clientMap      = make(map[C.uintptr_t]arksdk.ArkClient)
	clientMapMutex sync.Mutex
	clientHandleID uintptr

	contextMap      = make(map[C.uintptr_t]context.Context)
	contextMapMutex sync.Mutex
	contextHandleID uintptr
)

func generateClientHandle() C.uintptr_t {
	clientMapMutex.Lock()
	defer clientMapMutex.Unlock()
	clientHandleID++
	return C.uintptr_t(clientHandleID)
}

func generateContextHandle() C.uintptr_t {
	contextMapMutex.Lock()
	defer contextMapMutex.Unlock()
	contextHandleID++
	return C.uintptr_t(contextHandleID)
}

func getClient(handle C.uintptr_t) (arksdk.ArkClient, int, string) {
	clientMapMutex.Lock()
	defer clientMapMutex.Unlock()
	client, exists := clientMap[handle]
	if !exists {
		return nil, C.ARK_SDK_ERROR_INVALID_HANDLE, "invalid client handle"
	}
	return client, C.ARK_SDK_SUCCESS, ""
}

func getContext(handle C.uintptr_t) (context.Context, int, string) {
	contextMapMutex.Lock()
	defer contextMapMutex.Unlock()
	ctx, exists := contextMap[handle]
	if !exists {
		return nil, C.ARK_SDK_ERROR_INVALID_HANDLE, "invalid context handle"
	}
	return ctx, C.ARK_SDK_SUCCESS, ""
}

//export ArkClientNew
func ArkClientNew(errorMsg **C.char) C.uintptr_t {
	storeSvc, err := inmemorystore.NewConfigStore()
	if err != nil {
		*errorMsg = C.CString(err.Error())
		return 0
	}
	client, err := arksdk.NewCovenantlessClient(storeSvc)
	if err != nil {
		*errorMsg = C.CString(err.Error())
		return 0
	}
	handle := generateClientHandle()
	clientMapMutex.Lock()
	clientMap[handle] = client
	clientMapMutex.Unlock()
	*errorMsg = nil
	return handle
}

//export DestroyArkClient
func DestroyArkClient(handle C.uintptr_t) C.int {
	clientMapMutex.Lock()
	defer clientMapMutex.Unlock()
	_, exists := clientMap[handle]
	if exists {
		delete(clientMap, handle)
		return C.int(C.ARK_SDK_SUCCESS)
	}
	return C.int(C.ARK_SDK_ERROR_INVALID_HANDLE)
}

//export ArkClientInit
func ArkClientInit(handle C.uintptr_t, ctxHandle C.uintptr_t, aspUrl *C.char, password *C.char, errorMsg **C.char) C.int {
	if aspUrl == nil || password == nil {
		*errorMsg = C.CString("aspUrl or password is null")
		return C.int(C.ARK_SDK_ERROR_NULL_POINTER)
	}
	client, errCode, errStr := getClient(handle)
	if errCode != C.ARK_SDK_SUCCESS {
		*errorMsg = C.CString(errStr)
		return C.int(errCode)
	}
	ctx, errCode, errStr := getContext(ctxHandle)
	if errCode != C.ARK_SDK_SUCCESS {
		*errorMsg = C.CString(errStr)
		return C.int(errCode)
	}
	err := client.Init(ctx, arksdk.InitArgs{
		ClientType: arksdk.GrpcClient,
		WalletType: arksdk.SingleKeyWallet,
		AspUrl:     C.GoString(aspUrl),
		Password:   C.GoString(password),
	})
	if err != nil {
		*errorMsg = C.CString(err.Error())
		return C.int(C.ARK_SDK_ERROR_INITIALIZATION)
	}
	*errorMsg = nil
	return C.int(C.ARK_SDK_SUCCESS)
}

//export ArkClientUnlock
func ArkClientUnlock(handle C.uintptr_t, ctxHandle C.uintptr_t, password *C.char, errorMsg **C.char) C.int {
	if password == nil {
		*errorMsg = C.CString("password is null")
		return C.int(C.ARK_SDK_ERROR_NULL_POINTER)
	}
	client, errCode, errStr := getClient(handle)
	if errCode != C.ARK_SDK_SUCCESS {
		*errorMsg = C.CString(errStr)
		return C.int(errCode)
	}
	ctx, errCode, errStr := getContext(ctxHandle)
	if errCode != C.ARK_SDK_SUCCESS {
		*errorMsg = C.CString(errStr)
		return C.int(errCode)
	}
	err := client.Unlock(ctx, C.GoString(password))
	if err != nil {
		*errorMsg = C.CString(err.Error())
		return C.int(C.ARK_SDK_ERROR_UNLOCK_FAILED)
	}
	*errorMsg = nil
	return C.int(C.ARK_SDK_SUCCESS)
}

//export ArkClientReceive
func ArkClientReceive(handle C.uintptr_t, ctxHandle C.uintptr_t, offchainAddr **C.char, boardingAddr **C.char, errorMsg **C.char) C.int {
	if offchainAddr == nil || boardingAddr == nil {
		*errorMsg = C.CString("offchainAddr or boardingAddr is null")
		return C.int(C.ARK_SDK_ERROR_NULL_POINTER)
	}
	client, errCode, errStr := getClient(handle)
	if errCode != C.ARK_SDK_SUCCESS {
		*errorMsg = C.CString(errStr)
		return C.int(errCode)
	}
	ctx, errCode, errStr := getContext(ctxHandle)
	if errCode != C.ARK_SDK_SUCCESS {
		*errorMsg = C.CString(errStr)
		return C.int(errCode)
	}
	off, board, err := client.Receive(ctx)
	if err != nil {
		*errorMsg = C.CString(err.Error())
		return C.int(C.ARK_SDK_ERROR_RECEIVE_FAILED)
	}
	*offchainAddr = C.CString(off)
	*boardingAddr = C.CString(board)
	*errorMsg = nil
	return C.int(C.ARK_SDK_SUCCESS)
}

//export ArkClientBalance
func ArkClientBalance(handle C.uintptr_t, ctxHandle C.uintptr_t, computeExpiryDetails C.int, balance **C.char, errorMsg **C.char) C.int {
	if balance == nil {
		*errorMsg = C.CString("balance is null")
		return C.int(C.ARK_SDK_ERROR_NULL_POINTER)
	}
	client, errCode, errStr := getClient(handle)
	if errCode != C.ARK_SDK_SUCCESS {
		*errorMsg = C.CString(errStr)
		return C.int(errCode)
	}
	ctx, errCode, errStr := getContext(ctxHandle)
	if errCode != C.ARK_SDK_SUCCESS {
		*errorMsg = C.CString(errStr)
		return C.int(errCode)
	}
	bal, err := client.Balance(ctx, computeExpiryDetails != 0)
	if err != nil {
		*errorMsg = C.CString(err.Error())
		return C.int(C.ARK_SDK_ERROR_BALANCE_FAILED)
	}
	balJSON, err := json.Marshal(bal)
	if err != nil {
		*errorMsg = C.CString(err.Error())
		return C.int(C.ARK_SDK_ERROR_OPERATION_FAILED)
	}
	*balance = C.CString(string(balJSON))
	*errorMsg = nil
	return C.int(C.ARK_SDK_SUCCESS)
}

//export ArkClientSendAsync
func ArkClientSendAsync(handle C.uintptr_t, ctxHandle C.uintptr_t, withExpiryCoinselect C.int, receivers *C.Receiver, receiversCount C.int, txid **C.char, errorMsg **C.char) C.int {
	if receivers == nil || receiversCount <= 0 || txid == nil {
		*errorMsg = C.CString("receivers, receiversCount, or txid is invalid")
		return C.int(C.ARK_SDK_ERROR_INVALID_ARGUMENT)
	}
	client, errCode, errStr := getClient(handle)
	if errCode != C.ARK_SDK_SUCCESS {
		*errorMsg = C.CString(errStr)
		return C.int(errCode)
	}
	ctx, errCode, errStr := getContext(ctxHandle)
	if errCode != C.ARK_SDK_SUCCESS {
		*errorMsg = C.CString(errStr)
		return C.int(errCode)
	}
	goReceivers := make([]arksdk.Receiver, int(receiversCount))
	receiverSlice := (*[1 << 30]C.Receiver)(unsafe.Pointer(receivers))[:receiversCount:receiversCount]
	for i, r := range receiverSlice {
		if r.to == nil {
			*errorMsg = C.CString(fmt.Sprintf("receiver %d has null address", i))
			return C.int(C.ARK_SDK_ERROR_NULL_POINTER)
		}
		goReceivers[i] = arksdk.NewBitcoinReceiver(C.GoString(r.to), uint64(r.amount))
	}
	result, err := client.SendAsync(ctx, withExpiryCoinselect != 0, goReceivers)
	if err != nil {
		*errorMsg = C.CString(err.Error())
		return C.int(C.ARK_SDK_ERROR_SEND_FAILED)
	}
	*txid = C.CString(result)
	*errorMsg = nil
	return C.int(C.ARK_SDK_SUCCESS)
}

//export ArkClientClaim
func ArkClientClaim(handle C.uintptr_t, ctxHandle C.uintptr_t, txid **C.char, errorMsg **C.char) C.int {
	if txid == nil {
		*errorMsg = C.CString("txid is null")
		return C.int(C.ARK_SDK_ERROR_NULL_POINTER)
	}
	client, errCode, errStr := getClient(handle)
	if errCode != C.ARK_SDK_SUCCESS {
		*errorMsg = C.CString(errStr)
		return C.int(errCode)
	}
	ctx, errCode, errStr := getContext(ctxHandle)
	if errCode != C.ARK_SDK_SUCCESS {
		*errorMsg = C.CString(errStr)
		return C.int(errCode)
	}
	result, err := client.Claim(ctx)
	if err != nil {
		*errorMsg = C.CString(err.Error())
		return C.int(C.ARK_SDK_ERROR_CLAIM_FAILED)
	}
	*txid = C.CString(result)
	*errorMsg = nil
	return C.int(C.ARK_SDK_SUCCESS)
}

//export CreateContext
func CreateContext() C.uintptr_t {
	ctx := context.Background()
	handle := generateContextHandle()
	contextMapMutex.Lock()
	contextMap[handle] = ctx
	contextMapMutex.Unlock()
	return handle
}

//export DestroyContext
func DestroyContext(handle C.uintptr_t) C.int {
	contextMapMutex.Lock()
	defer contextMapMutex.Unlock()
	_, exists := contextMap[handle]
	if exists {
		delete(contextMap, handle)
		return C.int(C.ARK_SDK_SUCCESS)
	}
	return C.int(C.ARK_SDK_ERROR_INVALID_HANDLE)
}

//export FreeString
func FreeString(str *C.char) {
	C.free(unsafe.Pointer(str))
}

func main() {}
