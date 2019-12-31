#include "sm2operation.h"
#include <QDebug>

//SM2 Sources
typedef struct SM2_Ciphertext_st SM2_Ciphertext;
DECLARE_ASN1_FUNCTIONS(SM2_Ciphertext)

        struct SM2_Ciphertext_st {
                    BIGNUM *C1x;
                    BIGNUM *C1y;
                    ASN1_OCTET_STRING *C3;
                    ASN1_OCTET_STRING *C2;
        };

ASN1_SEQUENCE(SM2_Ciphertext) = {
            ASN1_SIMPLE(SM2_Ciphertext, C1x, BIGNUM),
            ASN1_SIMPLE(SM2_Ciphertext, C1y, BIGNUM),
            ASN1_SIMPLE(SM2_Ciphertext, C3, ASN1_OCTET_STRING),
            ASN1_SIMPLE(SM2_Ciphertext, C2, ASN1_OCTET_STRING),
} ASN1_SEQUENCE_END(SM2_Ciphertext)

IMPLEMENT_ASN1_FUNCTIONS(SM2_Ciphertext)
//SM2 Sources END

int Sm2Opt::bin2hex(const unsigned char *bin, int len, char *hex)
{
    int ret = 0;
    int i;
    char *p;
    p = hex;
    char h,l;

    for(i=0; i<len; i++)
    {
        h = (bin[i]&0xf0)>>4;
        l = bin[i]&0x0f;
        *p++ = h>9?(h-10+'A'):(h+'0');
        *p++ = l>9?(l-10+'A'):(l+'0');
    }
    *p = 0;
    ret = p-hex;
    return ret;
}

int Sm2Opt::hex2bin(const char *hex, int len, unsigned char *bin)
{
    int i;
    int l;

    for(i=0; i<len; i++)
    {
        l = hex[i]>'9'?(hex[i]-'A'+10):(hex[i]-'0');
        if(i%2==0){
            bin[i/2] = (l&0x0f)<<4;
        }else{
            bin[i/2] |= l&0x0f;
        }
    }
    return len/2;
}

//EVP_PKEY_CTX * Sm2Opt::importSm2(const char *pubk, const char *privk)
//{
////    qDebug() << pubk;
////    qDebug() << privk;
//    int i;
//    int offset = 0;
//    char buf[MAX_BUF_SM2];
//    //set curve group
//    EC_KEY *key = EC_KEY_new();
//    if(key==NULL){qDebug() << __LINE__; return NULL;}
//    EC_GROUP *group = EC_GROUP_new_by_curve_name(NID_sm2);
//    if(group==NULL){ qDebug() << __LINE__; return NULL;}
//    if(!EC_KEY_set_group(key,group)){ qDebug() << __LINE__; return NULL;}
//    //set key
//    BIGNUM *bn_pubk = BN_new();
//    if(bn_pubk==NULL){ qDebug() << __LINE__; return NULL;}
//    BIGNUM *bn_privk = BN_new();
//    if(bn_privk==NULL){ qDebug() << __LINE__; return NULL;}
//    if(BN_hex2bn(&bn_privk, privk)==0){
//        qDebug() << __LINE__;
//        qDebug() << strlen(privk) << ">>>" << privk;
//        return NULL;}
//    //set privk
//    if(!EC_KEY_set_private_key(key,bn_privk)){ qDebug() << __LINE__; return NULL;}
//    //set pubk DER
//    if(strlen(pubk)==128){
//        buf[0] = '0';
//        buf[1] = '4';
//        offset = 2;
//    }
//    for(i=0; i<strlen(pubk); i++)
//            buf[offset+i] = pubk[i];

//    if(BN_hex2bn(&bn_pubk,buf)==0){
//        qDebug() << __LINE__;
//        qDebug() << strlen(pubk) << ">>>" << pubk;
//        qDebug() << strlen(buf) << ">>>" << buf;
//        return NULL;}
//    EC_POINT *point = EC_POINT_bn2point(group, bn_pubk,NULL,NULL);
//    if(point == NULL){ qDebug() << __LINE__; return NULL;}
//    if(!EC_KEY_set_public_key(key,point)){ qDebug() << __LINE__; return NULL;}
//    if(!EC_KEY_check_key(key)){ qDebug() << __LINE__; return NULL;}
//    printf("sm2 key checked correct.\n");
//    //EVP
//    EVP_PKEY *pkey = EVP_PKEY_new();
//    if(pkey==NULL){ qDebug() << __LINE__; return NULL;}
//    if(!EVP_PKEY_assign(pkey, NID_sm2, key)){ qDebug() << __LINE__; return NULL;}
//    if(!EVP_PKEY_set_alias_type(pkey, NID_sm2)){ qDebug() << __LINE__; return NULL;}
//    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pkey, NULL);
//    if(ctx==NULL){ qDebug() << __LINE__; return NULL;}
//    printf("import sm2 success.\n");
//    return ctx;
////    return NULL;
//}

int Sm2Opt::importSm2_2(const char *pubk, const char *privk, EVP_PKEY_CTX **pctx)
{
//    qDebug() << pubk;
 //   qDebug() << privk;
    int i;
    int offset = 0;
    char buf[MAX_BUF_SM2];

    //set curve group
    EC_KEY *key = EC_KEY_new();
    if(key==NULL){ return __LINE__;}
    EC_GROUP *group = EC_GROUP_new_by_curve_name(NID_sm2);
    if(group==NULL){  return -1;}
    if(!EC_KEY_set_group(key,group)){  return __LINE__;}
    //set key
    BIGNUM *bn_pubk = BN_new();
    if(bn_pubk==NULL){  return __LINE__;}
    BIGNUM *bn_privk = BN_new();
    if(bn_privk==NULL){  return __LINE__;}
    if(BN_hex2bn(&bn_privk, privk)==0){

        qDebug() << strlen(privk) << ">>>" << privk;
        return __LINE__;}
    //set privk
    if(!EC_KEY_set_private_key(key,bn_privk)){  return __LINE__;}
    //set pubk DER
    if(strlen(pubk)==128){
        buf[0] = '0';
        buf[1] = '4';
        offset = 2;
    }
    for(i=0; i<strlen(pubk); i++)
            buf[offset+i] = pubk[i];

    if(BN_hex2bn(&bn_pubk,buf)==0){

        qDebug() << strlen(pubk) << ">>>" << pubk;
        qDebug() << strlen(buf) << ">>>" << buf;
        return __LINE__;}
    EC_POINT *point = EC_POINT_bn2point(group, bn_pubk,NULL,NULL);
    if(point == NULL){  return __LINE__;}
    if(!EC_KEY_set_public_key(key,point)){  return __LINE__;}
    if(!EC_KEY_check_key(key)){  return __LINE__;}
    printf("sm2 key checked correct.\n");
    //EVP
    EVP_PKEY *pkey = EVP_PKEY_new();
    if(pkey==NULL){  return __LINE__;}
    if(!EVP_PKEY_assign(pkey, NID_sm2, key)){  return __LINE__;}
    if(!EVP_PKEY_set_alias_type(pkey, NID_sm2)){  return __LINE__;}
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pkey, NULL);
    if(ctx==NULL){  return __LINE__;}
    printf("import sm2 success.\n");
    *pctx = ctx;
    return 1;
}

int Sm2Opt::importSm2Ciphertext(const char *C1x, const char *C1y,
                const char *C3, const char *C2,
                unsigned char *out, int *outL)
{
    unsigned char binC3[MAX_BUF_SM2];
    unsigned char binC2[MAX_BUF_SM2];
    unsigned char *p;
    //OBJ
    BIGNUM *bn_C1x = BN_new();
    if(bn_C1x==NULL) return 0;
    BIGNUM *bn_C1y = BN_new();
    if(bn_C1y==NULL) return 0;
    ASN1_OCTET_STRING *asn1_C3 = ASN1_OCTET_STRING_new();
    if(asn1_C3==NULL) return 0;
    ASN1_OCTET_STRING *asn1_C2 = ASN1_OCTET_STRING_new();
    if(asn1_C2==NULL) return 0;
    //set
    if(BN_hex2bn(&bn_C1x,C1x)==0) return 0;
    if(BN_hex2bn(&bn_C1y,C1y)==0) return 0;
    int binC3L = hex2bin(C3,strlen(C3),binC3);
    int binC2L = hex2bin(C2,strlen(C2),binC2);
    if(!ASN1_OCTET_STRING_set(asn1_C3,binC3,binC3L)) return 0;
    if(!ASN1_OCTET_STRING_set(asn1_C2,binC2,binC2L)) return 0;
    //sm2 ciphertext
    SM2_Ciphertext *ciphertext = SM2_Ciphertext_new();
    if(ciphertext==NULL) return 0;
    ciphertext->C1x = bn_C1x;
    ciphertext->C1y = bn_C1y;
    ciphertext->C3 = asn1_C3;
    ciphertext->C2 = asn1_C2;
    //output
    p = out;
    *outL = i2d_SM2_Ciphertext(ciphertext, &p);
    printf("import sm2 ciphertext success.\n");
    return *outL;
}

int Sm2Opt::exportSm2Ciphertext(char *in, int inl, char *out, int *outl)
{
    int ret = 0;
    unsigned char *q = (unsigned char *)out;
    const unsigned char *p = (unsigned char*)in;
    SM2_Ciphertext * sm2_ciphertext = d2i_SM2_Ciphertext(nullptr, &p, inl);
    if(sm2_ciphertext==nullptr) return ret;
    char *C1x = BN_bn2hex(sm2_ciphertext->C1x);
    char *C1y = BN_bn2hex(sm2_ciphertext->C1y);
    memcpy(q, C1x, strlen(C1x));
    q+=strlen(C1x);
    memcpy(q, C1y, strlen(C1y));
    q+=strlen(C1y);
    memcpy(q,sm2_ciphertext->C3->data,sm2_ciphertext->C3->length);
    q += sm2_ciphertext->C3->length;
    memcpy(q,sm2_ciphertext->C2->data,sm2_ciphertext->C2->length);
    q += sm2_ciphertext->C2->length;
    ret = q - (unsigned char*)out;
    *outl = ret;
    return  ret;
}

int Sm2Opt::sm2Decrypt(EVP_PKEY_CTX *ctx, unsigned char *in, int inL,
                unsigned char *out, int *outL)
{
    if(!EVP_PKEY_decrypt_init(ctx)) return 0;
    size_t len = *outL;
    if(!EVP_PKEY_decrypt(ctx, out, &len, in, inL)) return 0;
    printf("sm2 decrypt done.");
    *outL = len;
    return *outL;
}

int Sm2Opt::sm2Encrypt(EVP_PKEY_CTX *ctx, unsigned char *in, int inL,
                unsigned char *out, int *outL)
{
    if(!EVP_PKEY_encrypt_init(ctx)) return 0;
    size_t len = *outL;
    if(!EVP_PKEY_encrypt(ctx, out, &len, in, inL)) return 0;
    printf("sm2 encrypt done.");
    *outL = len;
    return *outL;
}

Sm2Opt::Sm2Opt()
{

}
