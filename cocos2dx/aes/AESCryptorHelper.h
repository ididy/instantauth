//
//  AESCryptorHelper.h
//  InstantAuth
//
//  Created by Jeong YunWon on 13. 3. 21..
//
//

#ifndef InstantAuth_AESCryptorHelper_h
#define InstantAuth_AESCryptorHelper_h

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/types.h>

ssize_t encrypt_aes256(const unsigned char *src, const size_t len, const unsigned char *secret_key, const unsigned char *ivec, unsigned char *dest);
ssize_t decrypt_aes256(const unsigned char *src, const size_t len, const unsigned char *secret_key, const unsigned char *ivec, unsigned char *dest);

#ifdef __cplusplus
}
#endif

#endif
