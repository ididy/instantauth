//
//  AESCryptorHelper.m
//  InstantAuth
//
//  Created by Jeong YunWon on 13. 3. 21..
//
//

#include "AESCryptorHelper.h"

#import <FoundationExtension/FoundationExtension.h>
#import <CommonCrypto/CommonCrypto.h>

extern NSData *NSDataCommonCryptoCrypt(CCOperation operation, NSData *data, NSData *key, CCAlgorithm algorithm, CCOptions options, size_t keyLength, size_t blockSize);

long encrypt_aes256(const unsigned char *src, const long len, const char *secret_key, const unsigned long secret_key_len, unsigned char *dest) {
    NSData *input = [NSData dataWithBytesNoCopy:(void *)src length:len freeWhenDone:NO];
    NSData *key = [NSData dataWithBytesNoCopy:(void *)secret_key length:secret_key_len freeWhenDone:NO];
//    NSData *output = NSDataCommonCryptoCrypt(kCCEncrypt, input, key, kCCAlgorithmAES128, kCCOptionPKCS7Padding, kCCKeySizeAES256, kCCBlockSizeAES128);
//    memcpy(dest, output.bytes, output.length);


    CCOperation operation = kCCEncrypt;
    CCAlgorithm algorithm = kCCAlgorithmAES128;
    CCOptions options = kCCOptionPKCS7Padding;
    NSData *data = input;
    size_t keyLength = kCCKeySizeAES256;
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

    CCCryptorStatus status = CCCrypt(operation, algorithm, options, keyBytes, keyLength, 0,
                                     data.bytes, data.length, dest, bufSize, &outSize);

    if (status != kCCSuccess) {
        return -1;
    }

    return outSize;
}
