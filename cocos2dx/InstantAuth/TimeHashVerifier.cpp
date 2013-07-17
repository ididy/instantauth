//
//  TimeHashVerifier.cpp
//  InstantAuth
//
//  Created by Jeong YunWon on 13. 3. 6..
//
//

#include "SHA1.h"
#include "TimeHashVerifier.h"

namespace cocos2d { namespace extension { namespace instantauth {

    CCData *TimeHashVerifier::encode_verification(CCString *private_key, CCString *public_key, CCString *secret_key) {
        time_t now = this->time_gen(NULL);
        CSHA1 hexhash;
        char timehex[9] = {0,};
        sprintf(timehex, "%08lx", now);
        hexhash.Update((UINT_8 *)private_key->getCString(), private_key->length());
        hexhash.Update((UINT_8 *)public_key->getCString(), public_key->length());
        hexhash.Update((UINT_8 *)timehex, 8);
        hexhash.Final();
        unsigned char hexhashbin[20];
        hexhash.GetHash(hexhashbin);
        char hexhashhex[41] = {0,};
        for (int i = 0; i < 20; i++) {
            sprintf(hexhashhex + i * 2, "%02x", hexhashbin[i]);
        }
        int verification_len = public_key->length() + 1 + 8 + 40;
        char verification[verification_len + 1];
        bzero(verification, verification_len + 1);
        sprintf(verification, "%s$%8lx%s", public_key->getCString(), now, hexhashhex);
        CCData *data = new CCData(new CCData((unsigned char *)verification, verification_len));
        //data->autorelease();
        return data;
    }

    CCData *TimeHashVerifier::merge_verification_data(CCData *verification, CCData *data, CCString *secret_key) {
        int bufferlen = verification->getSize() + 1 + data->getSize();
        char buffer[bufferlen + 1];
        buffer[bufferlen] = 0;
        int veriflen = verification->getSize();
        memcpy(buffer, verification->getBytes(), veriflen);
        buffer[veriflen] = '$';
        memcpy(buffer + veriflen + 1, data->getBytes(), data->getSize());
        CCData *mdata = new CCData(new CCData((unsigned char *)buffer, bufferlen));
        //mdata->autorelease();
        return mdata;
    }

    VerifierDestructedData TimeHashVerifier::divide_verification_and_data(CCData *raw_data, CCString *secret_key) {
        std::string data(raw_data->getBytes(), raw_data->getBytes() + raw_data->getSize());
        size_t pos1 = data.find("$") + 1;
        std::string verification1 = data.substr(0, pos1);
        data.erase(0, pos1);
        size_t pos2 = data.find("$");
        std::string verification2 = data.substr(0, pos2);
        data.erase(0, pos2 + 1);
        return VerifierDestructedData(NULL, new CCString(verification1 + verification2), new CCData(raw_data->getBytes() + pos1 + pos2 + 1, raw_data->getSize() - (pos1 + pos2 + 1)));
    }
    
    CCString *TimeHashVerifier::public_key_from_verification(CCString *verification, CCString *secret_key) {
        std::string data = verification->m_sString;
        size_t pos = data.find("$");
        std::string public_key = data.substr(0, pos);
        return new CCString(public_key);
    }
    
    bool TimeHashVerifier::verify(VerifierDestructedData destructed, CCString *private_key, CCString *secret_key) {
        return true; // FIXME: implmement here later
    }
    
} } }
