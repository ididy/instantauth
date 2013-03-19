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
        int hexhash_len = private_key->length() + public_key->length() + 8;
        CSHA1 hexhash;
        char timehex[9] = {0,};
        sprintf(timehex, "%8lx", now);
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
        int verification_len = public_key->length() + 1 + 8 + hexhash_len;
        char verification[verification_len + 1];
        sprintf(verification, "%s$%8lx%s", public_key->getCString(), now, hexhashhex);
        CCData *data = new CCData(new CCData((unsigned char *)verification, verification_len));
        //data->autorelease();
        return data;
    }

    CCData *TimeHashVerifier::merge_verification_data(CCData *verification, CCData *data, CCString *secret_key) {
        int bufferlen = verification->getSize() + 1 + data->getSize();
        char buffer[bufferlen + 1];
        buffer[bufferlen] = 0;
        sprintf(buffer, "%s$%s", verification->getBytes(), data->getBytes());
        CCData *mdata = new CCData(new CCData((unsigned char *)buffer, bufferlen));
        //mdata->autorelease();
        return mdata;
    }

} } }
