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

    class AESCryptor: Cryptor {
    public:
        virtual CCData *encrypt(CCData *data, CCString *secret_key);
        virtual CCData *encrypt_data(CCData *data, CCString *secret_key, CCString *private_key);
    };

} } }

#endif /* defined(__InstantAuth__AESCryptor__) */