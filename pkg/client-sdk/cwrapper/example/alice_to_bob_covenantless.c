#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "ark_sdk.h"

#define ASP_URL "localhost:7070"
#define PASSWORD "password"

uintptr_t setupArkClient() {
    char* errorMsg = NULL;
    uintptr_t client = ArkClientNew(&errorMsg);
    if (client == 0) {
        printf("Failed to create Ark client: %s\n", errorMsg);
        FreeString(errorMsg);
        exit(1);
    }

    uintptr_t ctx = CreateContext();

    if (ArkClientInit(client, ctx, ASP_URL, PASSWORD, &errorMsg) != ARK_SDK_SUCCESS) {
        printf("Failed to initialize client: %s\n", errorMsg);
        FreeString(errorMsg);
        DestroyContext(ctx);
        exit(1);
    }

    if (ArkClientUnlock(client, ctx, PASSWORD, &errorMsg) != ARK_SDK_SUCCESS) {
        printf("Failed to unlock client: %s\n", errorMsg);
        FreeString(errorMsg);
        DestroyContext(ctx);
        exit(1);
    }

    DestroyContext(ctx);
    return client;
}

void runCommand(const char* command) {
    int status = system(command);
    if (status != 0) {
        printf("Command failed: %s\n", command);
        exit(1);
    }
}

void generateBlock() {
    runCommand("nigiri rpc generatetoaddress 1 bcrt1qgqsguk6wax7ynvav4zys5x290xftk49h5agg0l");
    sleep(6);
}

void printBalance(uintptr_t client, uintptr_t ctx, const char* user) {
    char* balance = NULL;
    char* errorMsg = NULL;
    if (ArkClientBalance(client, ctx, 0, &balance, &errorMsg) == ARK_SDK_SUCCESS) {
        printf("%s balance: %s\n", user, balance);
        FreeString(balance);
    } else {
        printf("Failed to get %s balance: %s\n", user, errorMsg);
        FreeString(errorMsg);
    }
}

int main() {
    char* errorMsg = NULL;
    uintptr_t ctx = CreateContext();

    printf("Alice is setting up her ark wallet...\n");
    uintptr_t aliceClient = setupArkClient();

    printf("Alice is acquiring onchain funds...\n");
    char *aliceOffchainAddr = NULL, *aliceBoardingAddr = NULL;
    if (ArkClientReceive(aliceClient, ctx, &aliceOffchainAddr, &aliceBoardingAddr, &errorMsg) != ARK_SDK_SUCCESS) {
        printf("Failed to get Alice's addresses: %s\n", errorMsg);
        FreeString(errorMsg);
        DestroyContext(ctx);
        exit(1);
    }

    char command[256];
    snprintf(command, sizeof(command), "nigiri faucet %s", aliceBoardingAddr);
    runCommand(command);

    sleep(5);

    printf("Alice is onboarding with 100000000 sats offchain...\n");
    printBalance(aliceClient, ctx, "Alice");

    printf("Alice claiming onboarding funds...\n");
    char* aliceClaimTxid = NULL;
    if (ArkClientClaim(aliceClient, ctx, &aliceClaimTxid, &errorMsg) == ARK_SDK_SUCCESS) {
        printf("Alice claimed onboarding funds in round %s\n", aliceClaimTxid);
        FreeString(aliceClaimTxid);
    } else {
        printf("Failed to claim onboarding funds: %s\n", errorMsg);
        FreeString(errorMsg);
        DestroyContext(ctx);
        exit(1);
    }

    // Bob sets up his Ark wallet
    printf("\nBob is setting up his ark wallet...\n");
    uintptr_t bobClient = setupArkClient();

    char *bobOffchainAddr = NULL, *bobBoardingAddr = NULL;
    if (ArkClientReceive(bobClient, ctx, &bobOffchainAddr, &bobBoardingAddr, &errorMsg) != ARK_SDK_SUCCESS) {
        printf("Failed to get Bob's addresses: %s\n", errorMsg);
        FreeString(errorMsg);
        DestroyContext(ctx);
        exit(1);
    }

    printBalance(bobClient, ctx, "Bob");

    printf("\nAlice is sending 1000 sats to Bob offchain...\n");
    Receiver receivers[1];
    receivers[0].to = bobOffchainAddr;
    receivers[0].amount = 1000;

    char* sendTxid = NULL;
    if (ArkClientSendAsync(aliceClient, ctx, 0, receivers, 1, &sendTxid, &errorMsg) == ARK_SDK_SUCCESS) {
        printf("Payment completed out of round. Txid: %s\n", sendTxid);
        FreeString(sendTxid);
    } else {
        printf("Failed to send async: %s\n", errorMsg);
        FreeString(errorMsg);
        DestroyContext(ctx);
        exit(1);
    }

    generateBlock();

    sleep(5);

    printf("\n");
    printBalance(aliceClient, ctx, "Alice");
    printBalance(bobClient, ctx, "Bob");

    printf("\nBob is claiming the incoming payment...\n");
    char* bobClaimTxid = NULL;
    if (ArkClientClaim(bobClient, ctx, &bobClaimTxid, &errorMsg) == ARK_SDK_SUCCESS) {
        printf("Bob claimed the incoming payment in round %s\n", bobClaimTxid);
        FreeString(bobClaimTxid);
    } else {
        printf("Failed to claim incoming payment: %s\n", errorMsg);
        FreeString(errorMsg);
        DestroyContext(ctx);
        exit(1);
    }

    // Cleanup
    FreeString(aliceOffchainAddr);
    FreeString(aliceBoardingAddr);
    FreeString(bobOffchainAddr);
    FreeString(bobBoardingAddr);

    DestroyContext(ctx);

    return 0;
}
