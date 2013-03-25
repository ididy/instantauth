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

CCData *AESCryptor::encrypt(CCData *data, CCString *secret_key) {
    const long buffer_len = data->getSize() + 16;
    unsigned char *buffer = new unsigned char[buffer_len]; // 16 is the size of AES block

    long size = encrypt_aes256((const unsigned char *)data->getBytes(), data->getSize(), secret_key->getCString(), secret_key->length(), buffer);
    if (size < 0) {
        free(buffer);
        return 0;
    }
    return new CCData(buffer, size);
}

CCData *AESCryptor::encrypt_data(CCData *data, CCString *secret_key, CCString *private_key) {
    const long buffer_len = data->getSize() + 16;
    unsigned char *buffer = new unsigned char[buffer_len]; // 16 is the size of AES block

    long size = encrypt_aes256((const unsigned char *)data->getBytes(), data->getSize(), private_key->getCString(), private_key->length(), buffer);
    if (size < 0) {
        free(buffer);
        return 0;
    }
    return new CCData(buffer, size);
}
