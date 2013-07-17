//
//  RapidJsonCoder.cpp
//  InstantAuth
//
//  Created by Jeong YunWon on 13. 3. 6..
//
//

#include <rapidjson/rapidjson.h>
#include <rapidjson/document.h>
#include <rapidjson/stringbuffer.h>
#include <rapidjson/writer.h>

#include "RapidJsonCoder.h"

namespace cocos2d { namespace extension { namespace instantauth {

    CCData *RapidJsonCoder::encode(void *raw_data) {
        rapidjson::Value *v = (rapidjson::Value *)raw_data;
        rapidjson::StringBuffer buffer;
        rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
        v->Accept(writer);
        return new CCData(new CCData((unsigned char *)buffer.GetString(), buffer.GetSize()));
    }
    
    void *RapidJsonCoder::decode(CCData *data) {
        rapidjson::Document *document = new rapidjson::Document();
        char strdata[data->getSize() + 1];
        memcpy(strdata, data->getBytes(), data->getSize());
        strdata[data->getSize()] = 0;
        document->Parse<0>(strdata);
        return document;
    }

    //----

    CCData *RapidJsonDataKeyVerifier::construct_data(CCData *raw_data, CCString *private_key, CCString *public_key, CCString *secret_key) {
        rapidjson::Document document;
        rapidjson::Value *value = (rapidjson::Document *)raw_data;
        value->AddMember(((CCString *)this->_key)->m_sString.c_str(), public_key->m_sString.c_str(), document.GetAllocator());
        return this->_coder->encode(value);
    }
    
    VerifierDestructedData RapidJsonDataKeyVerifier::destruct_data(CCData *raw_data, CCString *secret_key) {
        rapidjson::Document *_decoded_data = (rapidjson::Document *)this->_coder->decode(raw_data);
        rapidjson::Document& decoded_data = *_decoded_data;
        const char *_verification = decoded_data[((CCString *)this->_key)->m_sString.c_str()].GetString();
        CCString *verification = new CCString(_verification);
        return VerifierDestructedData(verification, verification, raw_data);
    }

} } }
