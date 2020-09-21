#include "aes.h"
#include "sha1.h"
#include "sha256.h"
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#define TEST_TINY_AES_IV  "0123456789ABCDEF"
#define TEST_TINY_AES_KEY "0123456789ABCDEF0123456789ABCDEF"

static const unsigned char aes_test_ofb_pt[64] =
{
    0x6B, 0xC1, 0xBE, 0xE2, 0x2E, 0x40, 0x9F, 0x96,
    0xE9, 0x3D, 0x7E, 0x11, 0x73, 0x93, 0x17, 0x2A,
    0xAE, 0x2D, 0x8A, 0x57, 0x1E, 0x03, 0xAC, 0x9C,
    0x9E, 0xB7, 0x6F, 0xAC, 0x45, 0xAF, 0x8E, 0x51,
    0x30, 0xC8, 0x1C, 0x46, 0xA3, 0x5C, 0xE4, 0x11,
    0xE5, 0xFB, 0xC1, 0x19, 0x1A, 0x0A, 0x52, 0xEF,
    0xF6, 0x9F, 0x24, 0x45, 0xDF, 0x4F, 0x9B, 0x17,
    0xAD, 0x2B, 0x41, 0x7B, 0xE6, 0x6C, 0x37, 0x10
};


static const unsigned char aes_test_ctr_ct[3][48] =
{
    { 0xE4, 0x09, 0x5D, 0x4F, 0xB7, 0xA7, 0xB3, 0x79,
      0x2D, 0x61, 0x75, 0xA3, 0x26, 0x13, 0x11, 0xB8 },
    { 0x51, 0x04, 0xA1, 0x06, 0x16, 0x8A, 0x72, 0xD9,
      0x79, 0x0D, 0x41, 0xEE, 0x8E, 0xDA, 0xD3, 0x88,
      0xEB, 0x2E, 0x1E, 0xFC, 0x46, 0xDA, 0x57, 0xC8,
      0xFC, 0xE6, 0x30, 0xDF, 0x91, 0x41, 0xBE, 0x28 },
    { 0xC1, 0xCF, 0x48, 0xA8, 0x9F, 0x2F, 0xFD, 0xD9,
      0xCF, 0x46, 0x52, 0xE9, 0xEF, 0xDB, 0x72, 0xD7,
      0x45, 0x40, 0xA4, 0x2B, 0xDE, 0x6D, 0x78, 0x36,
      0xD5, 0x9A, 0x5C, 0xEA, 0xAE, 0xF3, 0x10, 0x53,
      0x25, 0xB2, 0x07, 0x2F }
};
unsigned char data[17] = "1234567890123457";
void test_aes(void)
{
    aes_context ctx;
    aes_xts_context ctx_xts;
    uint8_t iv[16];
    uint8_t private_key[32];


    unsigned char data_encrypt[64];
    unsigned char data_decrypt[64];
    /*
    AES-CBC
    **/
    /* encrypt */
    memcpy(iv, TEST_TINY_AES_IV, strlen(TEST_TINY_AES_IV));
    memcpy(private_key, TEST_TINY_AES_KEY, strlen(TEST_TINY_AES_KEY));
    memset(data_encrypt, 0x0, sizeof(data_encrypt));

    aes_setkey_enc(&ctx, (uint8_t *) private_key, 128);
    aes_crypt_cbc(&ctx, 1, strlen(data), iv, data, data_encrypt);
   // printf("aes_crypt_cbc:%s\r\n", data_encrypt);


    /* decrypt */
    memcpy(iv, TEST_TINY_AES_IV, strlen(TEST_TINY_AES_IV));
    memcpy(private_key, TEST_TINY_AES_KEY, strlen(TEST_TINY_AES_KEY));
    memset(data_decrypt, 0x0, sizeof(data_decrypt));

    aes_setkey_dec(&ctx, (uint8_t *) private_key, 128);
    aes_crypt_cbc(&ctx, 0, strlen(data), iv, data_encrypt, data_decrypt);
  //  printf("aes_crypt_cbc:%s\r\n", data_decrypt);
    if(memcmp(data, data_decrypt, strlen(data)) == 0)
    {
        printf("AES_CBC passed!\n");

    }
    else
    {
        printf("AES_CBC  failed!");

    }
    /*
    AES-ECB
    **/
    /* encrypt */
    memcpy(iv, TEST_TINY_AES_IV, strlen(TEST_TINY_AES_IV));
    memcpy(private_key, TEST_TINY_AES_KEY, strlen(TEST_TINY_AES_KEY));
    memset(data_encrypt, 0x0, sizeof(data_encrypt));

    aes_setkey_enc(&ctx, (uint8_t*)private_key, 128);
    aes_crypt_ecb(&ctx, 1, data, data_encrypt);
   // printf("aes_crypt_ecb:%s\r\n", data_encrypt);


    /* decrypt */
    memcpy(iv, TEST_TINY_AES_IV, strlen(TEST_TINY_AES_IV));
    memcpy(private_key, TEST_TINY_AES_KEY, strlen(TEST_TINY_AES_KEY));
    memset(data_decrypt, 0x0, sizeof(data_decrypt));

    aes_setkey_dec(&ctx, (uint8_t*)private_key, 128);
    aes_crypt_ecb(&ctx, 0, data_encrypt, data_decrypt);
   // printf("aes_crypt_ecb:%s\r\n", data_decrypt);
    if (memcmp(data, data_decrypt, strlen(data)) == 0)
    {
        printf("AES_ECB passed!\n");

    }
    else
    {
        printf("AES_ECB  failed!");

    }
    /*
    AES-XTS
    **/
    memset(data_encrypt, 0x0, sizeof(data_encrypt));
    memcpy(iv, TEST_TINY_AES_IV, strlen(TEST_TINY_AES_IV));
    memcpy(private_key, TEST_TINY_AES_KEY, strlen(TEST_TINY_AES_KEY));

    aes_xts_setkey_enc(&ctx_xts, (uint8_t*)private_key, 256);
    aes_crypt_xts(&ctx_xts,1, strlen(data), iv, data, data_encrypt);
  //  printf("aes_crypt_xts:%s\r\n", data_encrypt);


    memcpy(iv, TEST_TINY_AES_IV, strlen(TEST_TINY_AES_IV));
    memcpy(private_key, TEST_TINY_AES_KEY, strlen(TEST_TINY_AES_KEY));
    memset(data_decrypt, 0x0, sizeof(data_decrypt));

    aes_xts_setkey_dec(&ctx_xts, (uint8_t*)private_key, 256);
    aes_crypt_xts(&ctx_xts, 0, strlen(data), iv, data_encrypt, data_decrypt);
   //printf("aes_crypt_xts:%s\r\n", data_decrypt);
    if (memcmp(data, data_decrypt, strlen(data)) == 0)
    {
        printf("AES_XTS passed!\n");

    }
    else
    {
        printf("AES_XTS  failed!");

    }

    /*
    AES-OFB
    **/
    size_t offset=0;
    /* encrypt */
    memcpy(iv, TEST_TINY_AES_IV, strlen(TEST_TINY_AES_IV));
    memcpy(private_key, TEST_TINY_AES_KEY, strlen(TEST_TINY_AES_KEY));
    memset(data_encrypt, 0x0, sizeof(data_encrypt));

    aes_setkey_enc(&ctx, (uint8_t*)private_key, 128);
    aes_crypt_ofb(&ctx, 64, &offset,iv , aes_test_ofb_pt, data_encrypt);

    /* decrypt */
     offset = 0;
     memcpy(iv, TEST_TINY_AES_IV, strlen(TEST_TINY_AES_IV));
     memcpy(private_key, TEST_TINY_AES_KEY, strlen(TEST_TINY_AES_KEY));
    memset(data_decrypt, 0x0, sizeof(data_decrypt));

    aes_setkey_enc(&ctx, (uint8_t*)private_key, 128);
    aes_crypt_ofb(&ctx, 64, &offset, iv, data_encrypt, data_decrypt);
    if (memcmp(aes_test_ofb_pt, data_decrypt, 64) == 0)
    {
        printf("aes_ofb passed!\n");

    }
    else
    {
        printf("aes_ofb  failed!");

    }

    /*
    AES-cfb128
    **/
    offset = 0;
    /* encrypt */
    memset(data_encrypt, 0x0, sizeof(data_encrypt));
    memcpy(iv, TEST_TINY_AES_IV, strlen(TEST_TINY_AES_IV));
    memcpy(private_key, TEST_TINY_AES_KEY, strlen(TEST_TINY_AES_KEY));

    aes_setkey_enc(&ctx, (uint8_t*)private_key, 128);
    aes_crypt_cfb128(&ctx, 1, 64,&offset, iv, aes_test_ofb_pt, data_encrypt);

    offset = 0;
    /* decrypt */
    memset(data_decrypt, 0x0, sizeof(data_decrypt));
    memcpy(iv, TEST_TINY_AES_IV, strlen(TEST_TINY_AES_IV));
    memcpy(private_key, TEST_TINY_AES_KEY, strlen(TEST_TINY_AES_KEY));

    aes_setkey_enc(&ctx, (uint8_t*)private_key, 128);
    aes_crypt_cfb128(&ctx, 0, 64, &offset, iv, data_encrypt, data_decrypt);
    if (memcmp(aes_test_ofb_pt, data_decrypt, 64) == 0)
    {
        printf("aes-cfb128 passed!\n");

    }
    else
    {
        printf("aes-cfb128  failed!");

    }

    /*
    AES-ctr
    **/
    offset = 0;
    unsigned char nonce_counter[16];
    unsigned char stream_block[16];
    /* encrypt */
    memset(data_encrypt, 0x0, sizeof(data_encrypt));
    memcpy(iv, TEST_TINY_AES_IV, strlen(TEST_TINY_AES_IV));
    memcpy(private_key, TEST_TINY_AES_KEY, strlen(TEST_TINY_AES_KEY));
    aes_setkey_enc(&ctx, (uint8_t*)private_key, 128);
    //16,32,36
    aes_crypt_ctr(&ctx, 16, &offset, iv, stream_block, data, data_encrypt);

    /* decrypt */
    offset = 0;
    memset(data_decrypt, 0x0, sizeof(data_decrypt));
    memcpy(iv, TEST_TINY_AES_IV, strlen(TEST_TINY_AES_IV));
    memcpy(private_key, TEST_TINY_AES_KEY, strlen(TEST_TINY_AES_KEY));
    aes_setkey_enc(&ctx, (uint8_t*)private_key, 128);
    //16,32,36
    aes_crypt_ctr(&ctx, 16, &offset, iv, stream_block, data_encrypt, data_decrypt);

    if (memcmp(data, data_decrypt, 16) == 0)
    {
        printf("aes-ctr passed!\n");

    }
    else
    {
        printf("aes-ctr  failed!");

    }
}


static const unsigned char sha1_test_buf[3][57] =
{
    { "abc" },
    { "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq" },
    { "" }
};
static const unsigned char sha1_test_sum[3][20] =
{
    { 0xA9, 0x99, 0x3E, 0x36, 0x47, 0x06, 0x81, 0x6A, 0xBA, 0x3E,
      0x25, 0x71, 0x78, 0x50, 0xC2, 0x6C, 0x9C, 0xD0, 0xD8, 0x9D },
    { 0x84, 0x98, 0x3E, 0x44, 0x1C, 0x3B, 0xD2, 0x6E, 0xBA, 0xAE,
      0x4A, 0xA1, 0xF9, 0x51, 0x29, 0xE5, 0xE5, 0x46, 0x70, 0xF1 },
    { 0x34, 0xAA, 0x97, 0x3C, 0xD4, 0xC4, 0xDA, 0xA4, 0xF6, 0x1E,
      0xEB, 0x2B, 0xDB, 0xAD, 0x27, 0x31, 0x65, 0x34, 0x01, 0x6F }
};

static const unsigned char sha256_test_buf[3][57] =
{
    { "abc" },
    { "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq" },
    { "" }
};

static const size_t sha256_test_buflen[3] =
{
    3, 56, 1000
};
static const unsigned char sha256_test_sum[6][32] =
{
    /*
     * SHA-224 test vectors
     */
    { 0x23, 0x09, 0x7D, 0x22, 0x34, 0x05, 0xD8, 0x22,
      0x86, 0x42, 0xA4, 0x77, 0xBD, 0xA2, 0x55, 0xB3,
      0x2A, 0xAD, 0xBC, 0xE4, 0xBD, 0xA0, 0xB3, 0xF7,
      0xE3, 0x6C, 0x9D, 0xA7 },
    { 0x75, 0x38, 0x8B, 0x16, 0x51, 0x27, 0x76, 0xCC,
      0x5D, 0xBA, 0x5D, 0xA1, 0xFD, 0x89, 0x01, 0x50,
      0xB0, 0xC6, 0x45, 0x5C, 0xB4, 0xF5, 0x8B, 0x19,
      0x52, 0x52, 0x25, 0x25 },
    { 0x20, 0x79, 0x46, 0x55, 0x98, 0x0C, 0x91, 0xD8,
      0xBB, 0xB4, 0xC1, 0xEA, 0x97, 0x61, 0x8A, 0x4B,
      0xF0, 0x3F, 0x42, 0x58, 0x19, 0x48, 0xB2, 0xEE,
      0x4E, 0xE7, 0xAD, 0x67 },

      /*
       * SHA-256 test vectors
       */
      { 0xBA, 0x78, 0x16, 0xBF, 0x8F, 0x01, 0xCF, 0xEA,
        0x41, 0x41, 0x40, 0xDE, 0x5D, 0xAE, 0x22, 0x23,
        0xB0, 0x03, 0x61, 0xA3, 0x96, 0x17, 0x7A, 0x9C,
        0xB4, 0x10, 0xFF, 0x61, 0xF2, 0x00, 0x15, 0xAD },
      { 0x24, 0x8D, 0x6A, 0x61, 0xD2, 0x06, 0x38, 0xB8,
        0xE5, 0xC0, 0x26, 0x93, 0x0C, 0x3E, 0x60, 0x39,
        0xA3, 0x3C, 0xE4, 0x59, 0x64, 0xFF, 0x21, 0x67,
        0xF6, 0xEC, 0xED, 0xD4, 0x19, 0xDB, 0x06, 0xC1 },
      { 0xCD, 0xC7, 0x6E, 0x5C, 0x99, 0x14, 0xFB, 0x92,
        0x81, 0xA1, 0xC7, 0xE2, 0x84, 0xD7, 0x3E, 0x67,
        0xF1, 0x80, 0x9A, 0x48, 0xA4, 0x97, 0x20, 0x0E,
        0x04, 0x6D, 0x39, 0xCC, 0xC7, 0x11, 0x2C, 0xD0 }
};
void test_sha1()
{
    unsigned char buf[1024];
    unsigned char sha1sum1[20];
    /**   
    sha1
    */
    memset(buf, 'a',1000);
    sha1_calculate(sha1_test_buf[0],3, sha1sum1);
    if (memcmp(sha1sum1, sha1_test_sum[0], 20) == 0)
    {

        printf("sha1 passed!\n");

    }
    else
    {
        printf("sha1  failed!");

    }
    /**
    sha1-hmac
    */
    unsigned char sha1sum[32];
    memset(buf, 'a', 1000);
    sha1_hmac_calculate(data,16, sha256_test_buf[0],56, sha1sum);
    for (uint8_t i = 0; i < 20; i++)
    {
        printf("%02x ", sha1sum[i]);
    }

    /**
    sha256
    */
    unsigned char output[32];
    sha256_calculate(sha256_test_buf[0],3, output,0);
    if (memcmp(output, sha256_test_sum[3], 32) == 0)
    {

        printf("sha256 passed!\n");

    }
    else
    {
        printf("sha256  failed!");

    }
}

/*
 * Checkup routine
 */
//int md5_self_test(int verbose)
//{
//    int i, ret = 0;
//    unsigned char md5sum[16];
//
//    for (i = 0; i < 7; i++)
//    {
//        if (verbose != 0)
//            printf("  MD5 test #%d: ", i + 1);
//
//        ret = md5_ret(md5_test_buf[i], md5_test_buflen[i], md5sum);
//        if (ret != 0)
//            goto fail;
//
//        if (memcmp(md5sum, md5_test_sum[i], 16) != 0)
//        {
//            ret = 1;
//            goto fail;
//        }
//
//        if (verbose != 0)
//            printf("passed\n");
//    }
//
//    if (verbose != 0)
//        printf("\n");
//
//    return(0);
//
//fail:
//    if (verbose != 0)
//        printf("failed\n");
//
//    return(ret);
//}

//static const unsigned char base64_test_dec[64] =
//{
//    0x24, 0x48, 0x6E, 0x56, 0x87, 0x62, 0x5A, 0xBD,
//    0xBF, 0x17, 0xD9, 0xA2, 0xC4, 0x17, 0x1A, 0x01,
//    0x94, 0xED, 0x8F, 0x1E, 0x11, 0xB3, 0xD7, 0x09,
//    0x0C, 0xB6, 0xE9, 0x10, 0x6F, 0x22, 0xEE, 0x13,
//    0xCA, 0xB3, 0x07, 0x05, 0x76, 0xC9, 0xFA, 0x31,
//    0x6C, 0x08, 0x34, 0xFF, 0x8D, 0xC2, 0x6C, 0x38,
//    0x00, 0x43, 0xE9, 0x54, 0x97, 0xAF, 0x50, 0x4B,
//    0xD1, 0x41, 0xBA, 0x95, 0x31, 0x5A, 0x0B, 0x97
//};
//
//static const unsigned char base64_test_enc[] =
//"JEhuVodiWr2/F9mixBcaAZTtjx4Rs9cJDLbpEG8i7hPK"
//"swcFdsn6MWwINP+Nwmw4AEPpVJevUEvRQbqVMVoLlw==";
//
///*
// * Checkup routine
// */
//int mbedtls_base64_self_test(int verbose)
//{
//    size_t len;
//    const unsigned char* src;
//    unsigned char buffer[128];
//
//    if (verbose != 0)
//        mbedtls_printf("  Base64 encoding test: ");
//
//    src = base64_test_dec;
//
//    if (mbedtls_base64_encode(buffer, sizeof(buffer), &len, src, 64) != 0 ||
//        memcmp(base64_test_enc, buffer, 88) != 0)
//    {
//        if (verbose != 0)
//            mbedtls_printf("failed\n");
//
//        return(1);
//    }
//
//    if (verbose != 0)
//        mbedtls_printf("passed\n  Base64 decoding test: ");
//
//    src = base64_test_enc;
//
//    if (mbedtls_base64_decode(buffer, sizeof(buffer), &len, src, 88) != 0 ||
//        memcmp(base64_test_dec, buffer, 64) != 0)
//    {
//        if (verbose != 0)
//            mbedtls_printf("failed\n");
//
//        return(1);
//    }
//
//    if (verbose != 0)
//        mbedtls_printf("passed\n\n");
//
//    return(0);
//}
int main()
{
    test_aes();
    test_sha1();


return 0;
}