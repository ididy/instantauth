//
//  RapidJsonCoder.h
//  InstantAuth
//
//  Created by Jeong YunWon on 13. 3. 6..
//
//

#ifndef __InstantAuth__RapidJsonCoder__
#define __InstantAuth__RapidJsonCoder__

#include "CCInstantAuthProtocol.h"

namespace cocos2d { namespace extension { namespace instantauth {

    class RapidJsonCoder: public Coder {
    public:
        virtual CCData *encode(void *data);
    };

    class RapidJsonDataKeyVerifier: public DataKeyVerifier {
    public:
        RapidJsonDataKeyVerifier(Coder *coder, CCString *key) : DataKeyVerifier(coder, key) { }
        virtual CCData *construct_data(CCData *raw_data, CCString *private_key, CCString *public_key, CCString *secret_key);
    };

} } }

#endif /* defined(__InstantAuth__RapidJsonCoder__) */
