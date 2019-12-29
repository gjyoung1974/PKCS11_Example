#include <iostream>
#include "cryptoki.h"   //cryptoki: https://en.wikipedia.org/wiki/PKCS_11
#include <dlfcn.h>      //dlfcn: dynamically load a shared object: https://pubs.opengroup.org/onlinepubs/7908799/xsh/dlfcn.h.html

CK_FUNCTION_LIST_PTR p11;
CK_SESSION_HANDLE hSession;
CK_C_GetFunctionList pGetFunctionList;
CK_RV rv;

int main() {

    //Path to our cryptoki library
    char m_module[] = "/usr/local/lib/softhsm/libsofthsm2.so";
    char *module = m_module;
    void *pDynLib;

    // Load PKCS #11 library
    pDynLib = dlopen(module, RTLD_NOW | RTLD_LOCAL);

    if (!pDynLib) {
        // Failed to load the PKCS #11 library
        fprintf(stderr, "Failed to load the PKCS #11 library");
        return 0;
    }


    //provide Slot ID and Slot PIN
    std::string spin = "1234";
    unsigned char *pin = (unsigned char *) spin.c_str();
    CK_SLOT_ID slotID = 0x724622e;

    // Retrieve the entry point for C_GetFunctionList
    pGetFunctionList = (CK_C_GetFunctionList) dlsym(pDynLib, "C_GetFunctionList");

    // Load the function list into our provider
    (*pGetFunctionList)(&p11);

    // Initialize the library
    rv = p11->C_Initialize(NULL_PTR);

    if (rv != CKR_OK) {
        fprintf(stderr, "ERROR: Could not initialize the library. rv=%s\n");
        exit(1);
    }

    // Open a RW session
    rv = p11->C_OpenSession(slotID, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL, NULL, &hSession);
    if (rv == CKR_SLOT_ID_INVALID) {
        fprintf(stderr, "ERROR: The slot does not exist.\n");
        return 1;
    }

    if (rv != CKR_OK) {
        fprintf(stderr, "ERROR: Could not open a session. rv=%s\n");
        return 1;
    }

    rv = p11->C_Login(hSession, CKU_USER, pin, 4);

    if (rv != CKR_OK) {
        if (rv == CKR_PIN_INCORRECT) {
            fprintf(stderr, "ERROR: The given user PIN does not match the one in the token.\n");
        } else {
            fprintf(stderr, "ERROR: Could not log in on the token. rv=%s\n");
        }
        return 1;
    }

//    //_CK_TOKEN_INFO tokenInfo;
//    _CK_SLOT_INFO slotInfo;
//    p11->C_GetSlotInfo(hSession, &slotInfo);
//    fprintf(stderr, reinterpret_cast<const char *>(slotInfo.manufacturerID));
//    fprintf(stderr, "\n");

    //Configure the RSA mechanism
    CK_MECHANISM keyGenMechanism = {CKM_RSA_PKCS_KEY_PAIR_GEN, NULL_PTR, 0};
    CK_BBOOL ckTrue = CK_TRUE;
    CK_OBJECT_HANDLE hPublicKey, hPrivateKey;
    CK_ULONG modulusBits = 4096;
    CK_BYTE publicExponent[] = {1, 0, 1};

    //Provide a public and private key template
    CK_ATTRIBUTE publicKeyTemplate[] = {
            {CKA_ENCRYPT,         &ckTrue,         sizeof(ckTrue)},
            {CKA_VERIFY,          &ckTrue,         sizeof(ckTrue)},
            {CKA_WRAP,            &ckTrue,         sizeof(ckTrue)},
            {CKA_TOKEN,           &ckTrue,         sizeof(ckTrue)},
            {CKA_MODULUS_BITS,    &modulusBits,    sizeof(modulusBits)},
            {CKA_PUBLIC_EXPONENT, &publicExponent, sizeof(publicExponent)}
    };

    CK_ATTRIBUTE privateKeyTemplate[] = {
            {CKA_PRIVATE,   &ckTrue, sizeof(ckTrue)},
            {CKA_SENSITIVE, &ckTrue, sizeof(ckTrue)},
            {CKA_DECRYPT,   &ckTrue, sizeof(ckTrue)},
            {CKA_SIGN,      &ckTrue, sizeof(ckTrue)},
            {CKA_UNWRAP,    &ckTrue, sizeof(ckTrue)},
            {CKA_TOKEN,     &ckTrue, sizeof(ckTrue)}
    };

    CK_ATTRIBUTE pubTemplate[] = {
            {CKA_PUBLIC_EXPONENT, NULL_PTR, 0},
            {CKA_MODULUS,         NULL_PTR, 0}
    };

    CK_BYTE_PTR public_exponent1 = NULL;
    CK_BYTE_PTR public_exponent2 = NULL;
    CK_ULONG public_exponent_len2 = 0;
    CK_BYTE_PTR modulus1 = NULL;
    CK_BYTE_PTR modulus2 = NULL;
    CK_ULONG modulus_len2 = 0;

    printf("Generate an RSA key pair: ");

    rv = p11->C_GenerateKeyPair(hSession, &keyGenMechanism, publicKeyTemplate, 6, privateKeyTemplate, 6, &hPublicKey,
                                &hPrivateKey);

    if (rv != CKR_OK) {
        printf("Failed to generate a keypair. rv=%s\n");
        return 1;
    }

    printf("OK\n");

    // Get the information from the public key
    rv = p11->C_GetAttributeValue(hSession, hPublicKey, pubTemplate, 2);
    if (rv != CKR_OK) {
        printf("Failed to get the modulus and pubexp. rv=%s\n");
        return 1;
    }

    // Get Attribute Values
    rv = p11->C_GetAttributeValue(hSession, hPrivateKey, pubTemplate, 2);

    if (rv == CKR_ATTRIBUTE_TYPE_INVALID) {
        printf("Failed. The modulus or pubexp does not exist\n");
        return 1;
    }

    if (rv != CKR_OK) {
        printf("Failed to get the size of modulus and pubexp. rv=%s\n");
        return 1;
    }

    //_CK_TOKEN_INFO tokenInfo;
    _CK_SLOT_INFO slotInfo;
    p11->C_GetSlotInfo(hSession, &slotInfo);
    fprintf(stderr, reinterpret_cast<const char *>(slotInfo.slotDescription));
    fprintf(stderr, "\n");

    return 0;
}
