//
//  JsonCppCoder.cpp
//  InstantAuth
//
//  Created by Jeong YunWon on 13. 8. 16..
//
//

#include <json/reader.h>
#include <json/value.h>
#include <json/writer.h>

#include "JsonCppCoder.h"

namespace cocos2d { namespace extension { namespace instantauth {

    CCData *JsonCppCoder::encode(void *raw_data) {
        Json::Value *v = (Json::Value *)raw_data;
        Json::FastWriter writer;
        std::string data = writer.write(*v);
        data.erase(data.length() - 1);
        return new CCData(new CCData((unsigned char *)data.c_str(), data.length()));
    }
    
    void *JsonCppCoder::decode(CCData *data) {
        Json::Reader reader;
        Json::Value *value = new Json::Value;
        char strdata[data->getSize() + 1];
        memcpy(strdata, data->getBytes(), data->getSize());
        strdata[data->getSize()] = 0;
        reader.parse(strdata, *value);
        return value;
    }

    //----

    CCData *JsonCppDataKeyVerifier::construct_data(CCData *raw_data, CCString *private_key, CCString *public_key, CCString *secret_key) {
        Json::Value& value = *((Json::Value *)raw_data);
        value[((CCString *)this->_key)->m_sString] = public_key->m_sString;
        return this->_coder->encode(raw_data);
    }
    
    VerifierDestructedData JsonCppDataKeyVerifier::destruct_data(CCData *raw_data, CCString *secret_key) {
        Json::Value *_value = (Json::Value *)this->_coder->decode(raw_data);
        Json::Value& value = *_value;
        std::string _verification = value[((CCString *)this->_key)->m_sString].asString();
        CCString *verification = new CCString(_verification);
        return VerifierDestructedData(verification, verification, raw_data);
    }

} } }
