#ifndef SM2OPERATION_H
#define SM2OPERATION_H
//#include <iostream>
#include <stdio.h>
#include <string.h>

#include "openssl/evp.h"
#include "openssl/ec.h"
#include "openssl/bn.h"
#include "openssl/asn1.h"
#include "openssl/asn1t.h"

#define MAX_BUF_SM2 4096


class Sm2Opt
{
public:
    Sm2Opt();
    int bin2hex(const unsigned char *bin, int len, char *hex);
    int hex2bin(const char *hex, int len, unsigned char *bin);
//    EVP_PKEY_CTX *importSm2(const char *pubk, const char *privk);
    int importSm2_2(const char *pubk, const char *privk, EVP_PKEY_CTX **pctx);
    int importSm2Ciphertext(const char *C1x, const char *C1y,
                    const char *C3, const char *C2,
                    unsigned char *out, int *outL);
    int sm2Decrypt(EVP_PKEY_CTX *ctx, unsigned char *in, int inL,
                    unsigned char *out, int *outL);
    int sm2Encrypt(EVP_PKEY_CTX *ctx, unsigned char *in, int inL,
                    unsigned char *out, int *outL);
};

#endif // SM2OPERATION_H
