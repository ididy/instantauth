//
//  AESCryptorHelper.m
//  InstantAuth
//
//  Created by Jeong YunWon on 13. 3. 21..
//
//

#include "AESCryptorHelper.h"

#import <Foundation/Foundation.h>
#import <CommonCrypto/CommonCrypto.h>

ssize_t encrypt_aes256(const unsigned char *src, const size_t len, const unsigned char *secret_key, const unsigned char *ivec, unsigned char *dest) {
    size_t keyLength = kCCKeySizeAES256;
    
    NSData *data = [NSData dataWithBytesNoCopy:(void *)src length:len freeWhenDone:NO];
    NSData *key = [NSData dataWithBytesNoCopy:(void *)secret_key length:keyLength freeWhenDone:NO];

    CCOperation operation = kCCEncrypt;
    CCAlgorithm algorithm = kCCAlgorithmAES128;
    CCOptions options = kCCOptionPKCS7Padding;
    size_t blockSize = kCCBlockSizeAES128;

    unsigned char keyBytes[keyLength];
    // safe-key
    NSInteger diff = keyLength - key.length;
    if (diff <= 0) {
        memcpy(keyBytes, key.bytes, keyLength);
    } else {
        bzero(keyBytes + key.length, diff); // zero padding
        memcpy(keyBytes, key.bytes, key.length);
    }

    size_t bufSize = data.length + blockSize;

    size_t outSize = 0;

    CCCryptorStatus status = CCCrypt(operation, algorithm, options, keyBytes, keyLength, ivec,
                                     data.bytes, data.length, dest, bufSize, &outSize);

    if (status != kCCSuccess) {
        return -1;
    }

    return outSize;
}

ssize_t decrypt_aes256(const unsigned char *src, const size_t len, const unsigned char *secret_key, const unsigned char *ivec, unsigned char *dest) {
    size_t keyLength = kCCKeySizeAES256;

    NSData *data = [NSData dataWithBytesNoCopy:(void *)src length:len freeWhenDone:NO];
    NSData *key = [NSData dataWithBytesNoCopy:(void *)secret_key length:keyLength freeWhenDone:NO];

    CCOperation operation = kCCDecrypt;
    CCAlgorithm algorithm = kCCAlgorithmAES128;
    CCOptions options = kCCOptionPKCS7Padding;
    size_t blockSize = kCCBlockSizeAES128;

    unsigned char keyBytes[keyLength];
    // safe-key
    NSInteger diff = keyLength - key.length;
    if (diff <= 0) {
        memcpy(keyBytes, key.bytes, keyLength);
    } else {
        bzero(keyBytes + key.length, diff); // zero padding
        memcpy(keyBytes, key.bytes, key.length);
    }

    size_t bufSize = data.length + blockSize;

    size_t outSize = 0;

    CCCryptorStatus status = CCCrypt(operation, algorithm, options, keyBytes, keyLength, ivec,
                                     data.bytes, data.length, dest, bufSize, &outSize);

    if (status != kCCSuccess) {
        return -1;
    }

    return outSize;
}
