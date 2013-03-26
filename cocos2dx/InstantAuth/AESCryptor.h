//
//  AESCryptor.h
//  InstantAuth
//
//  Created by Jeong YunWon on 13. 3. 21..
//
//

#ifndef __InstantAuth__AESCryptor__
#define __InstantAuth__AESCryptor__

#include "CCInstantAuthProtocol.h"

namespace cocos2d { namespace extension { namespace instantauth {

    class AES256Cryptor: public Cryptor {
    public:
        virtual CCData *encrypt_stream(CCData *data, CCString *secret_key);
        virtual CCData *encrypt_data(CCData *data, CCString *private_key, CCString *secret_key);
    };

} } }

#endif /* defined(__InstantAuth__AESCryptor__) */
