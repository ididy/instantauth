//
//  JsonCppCoder.h
//  InstantAuth
//
//  Created by Jeong YunWon on 13. 8. 16..
//
//

#ifndef __InstantAuth__JsonCppCoder__
#define __InstantAuth__JsonCppCoder__

#include "CCInstantAuthProtocol.h"

namespace cocos2d { namespace extension { namespace instantauth {

    class JsonCppCoder: public Coder {
    public:
        virtual CCData *encode(void *data);
        virtual void *decode(CCData *data);
    };

    class JsonCppDataKeyVerifier: public DataKeyVerifier {
    public:
        JsonCppDataKeyVerifier(Coder *coder, CCString *key) : DataKeyVerifier(coder, key) { }
        virtual CCData *construct_data(CCData *raw_data, CCString *private_key, CCString *public_key, CCString *secret_key);
        virtual VerifierDestructedData destruct_data(CCData *raw_data, CCString *secret_key);
    };
    
} } }


#endif /* defined(__InstantAuth__JsonCppCoder__) */
