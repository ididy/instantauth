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

long encrypt_aes256(const unsigned char *src, const long len, const char *secret_key, const unsigned long secret_key_len, const char *ivec, unsigned char *dest);

#ifdef __cplusplus
}
#endif

#endif
