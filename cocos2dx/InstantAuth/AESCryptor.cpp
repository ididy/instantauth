//
//  AESCryptor.cpp
//  InstantAuth
//
//  Created by Jeong YunWon on 13. 3. 21..
//
//

#include "AESCryptor.h"

#include "AESCryptorHelper.h"

using namespace cocos2d::extension::instantauth;

CCData *cap_iv(CCString *iv) {
    if (iv->length() >= 16) {
        return new CCData((unsigned char *)iv->getCString(), 16);
    }
    char padded_iv[17] = {0,};
    memcpy(padded_iv, iv->getCString(), iv->length());
    return new CCData(new CCData((unsigned char *)padded_iv, 16));
}

CCData *AES256Cryptor::encrypt_stream(CCData *data, CCString *secret_key) {
    const long buffer_len = data->getSize() + 16;
    unsigned char *buffer = new unsigned char[buffer_len]; // 16 is the size of AES block

    long size = encrypt_aes256((const unsigned char *)data->getBytes(), data->getSize(), secret_key->getCString(), secret_key->length(), 0, buffer);
    if (size < 0) {
        free(buffer);
        return 0;
    }
    return new CCData(buffer, size);
}

CCData *AES256Cryptor::encrypt_data(CCData *data, CCString *private_key, CCString *secret_key) {
    const long buffer_len = data->getSize() + 16;
    unsigned char *buffer = new unsigned char[buffer_len]; // 16 is the size of AES block

    CCData *iv = cap_iv(private_key);
    long size = encrypt_aes256((const unsigned char *)data->getBytes(), data->getSize(), secret_key->getCString(), secret_key->length(), (const unsigned char *)iv->getBytes(), buffer);
    if (size < 0) {
        free(buffer);
        return 0;
    }
    return new CCData(buffer, size);
}
