/*
 * $Id: _tea.c,v 1.25 2001/05/21 17:32:59 ams Exp $
 * Copyright 2001 Abhijit Menon-Sen <ams@wiw.org>
 */

#include <stdio.h>

#if defined(__APPLE__)
#  define COMMON_DIGEST_FOR_OPENSSL
#  include <CommonCrypto/CommonDigest.h>
#  define SHA1 CC_SHA1
#else
#  include <openssl/md5.h>
#endif

#include "tea.h"

unsigned char *str2md5(unsigned char *i, int l);

#define strtonl(s) (uint32_t)(*(s)|*(s+1)<<8|*(s+2)<<16|*(s+3)<<24)
#define nltostr(l, s) \
    do {                                    \
        *(s  )=(unsigned char)((l)      );  \
        *(s+1)=(unsigned char)((l) >>  8);  \
        *(s+2)=(unsigned char)((l) >> 16);  \
        *(s+3)=(unsigned char)((l) >> 24);  \
    } while (0)

int tea_blockSize(void)
{
    return 8; }
/* TEA is a 64-bit symmetric block cipher with a 128-bit key, developed
   by David J. Wheeler and Roger M. Needham, and described in their
   paper at <URL:http://www.cl.cam.ac.uk/ftp/users/djw3/tea.ps>.

   This implementation is based on their code in
   <URL:http://www.cl.cam.ac.uk/ftp/users/djw3/xtea.ps> */

struct tea *tea_setup(unsigned char *key, int rounds)
{
    struct tea *self = malloc(sizeof(struct tea));
    unsigned char *key_digest = str2md5(key, 16);

    if (self) {
        self->rounds = rounds;

        self->key[0] = strtonl(key_digest);
        self->key[1] = strtonl(key_digest+4);
        self->key[2] = strtonl(key_digest+8);
        self->key[3] = strtonl(key_digest+12);
    }
    free(key_digest);
    return self;
}

void tea_free(struct tea *self)
{
    free(self);
}
void tea_encryptBlock(struct tea *self,
                  unsigned char * input,
                  unsigned char * output)
{
  tea_crypt(self, input, output, 0);
}
void tea_decryptBlock(struct tea *self,
                  unsigned char * input,
                  unsigned char * output)
{
  tea_crypt(self, input, output, 1);
}
void tea_crypt(struct tea *self,
               unsigned char *input, unsigned char *output,
               int decrypt)
{
    int i, rounds;
    uint32_t delta = 0x9E3779B9, /* 2^31*(sqrt(5)-1) */
             *k, y, z, sum = 0;

    k = self->key;
    rounds = self->rounds;

    y = strtonl(input);
    z = strtonl(input+4);

    if (!decrypt) {
        for (i = 0; i < rounds; i++) {
            y += ((z << 4 ^ z >> 5) + z) ^ (sum + k[sum & 3]);
            sum += delta;
            z += ((y << 4 ^ y >> 5) + y) ^ (sum + k[sum >> 11 & 3]);
        }
    } else {
        sum = delta * rounds;
        for (i = 0; i < rounds; i++) {
            z -= ((y << 4 ^ y >> 5) + y) ^ (sum + k[sum >> 11 & 3]);
            sum -= delta;
            y -= ((z << 4 ^ z >> 5) + z) ^ (sum + k[sum & 3]);
        }
    }

    nltostr(y, output);
    nltostr(z, output+4);
}

unsigned char *str2md5(unsigned char *str, int length) {
    int n;
    MD5_CTX c;
    unsigned char *digest = (unsigned char *)malloc(length);

    MD5_Init(&c);

    while (length > 0) {
        if (length > 512) {
            MD5_Update(&c, str, 512);
        } else {
            MD5_Update(&c, str, length);
        }
        length -= 512;
        str += 512;
    }

    MD5_Final(digest, &c);

    return digest;
}
