//
//  InstantAuth.h
//  InstantAuth
//
//  Created by Jeong YunWon on 13. 3. 5..
//
//

#ifndef __CCInstantAuth__
#define __CCInstantAuth__

#include <cocos2d.h>
#include "CCData.h"

#include "CCInstantAuthProtocol.h"

namespace cocos2d { namespace extension {

    class CCInstantAuthSession;

    class CCInstantAuthContext {
    public:
        CCInstantAuthSession *session;
        void *data;
        void *userdata;
        CCInstantAuthContext(CCInstantAuthSession *session, void *data) {
            this->session = session;
            this->data = data;
            this->userdata = 0;
        }
    };

    class CCInstantAuth {
        instantauth::Coder *streamcoder;
        instantauth::Cryptor *cryptor;
        instantauth::Verifier *verifier;
        instantauth::Coder *datacoder;
        instantauth::SessionHandler *session_handler;
        CCString *secret_key;
    public:
        CCInstantAuth(instantauth::Coder *streamcoder, instantauth::Cryptor *cryptor, instantauth::Verifier *verifier, instantauth::Coder *datacoder, instantauth::SessionHandler *session_handler, CCString *secret_key) {
            this->streamcoder = streamcoder;
            this->cryptor = cryptor;
            this->verifier = verifier;
            this->datacoder = datacoder;
            this->session_handler = session_handler;
            this->secret_key = secret_key;
            assert(this->streamcoder);
            assert(this->cryptor);
            assert(this->verifier);
            assert(this->datacoder);
            assert(this->session_handler);
            assert(this->secret_key);
        }

        CCData *build_data(void *data, void *session);
        CCData *build_first_data(void *data, CCString *session_key);
        CCInstantAuthContext get_context(CCData *data);
        CCInstantAuthContext get_first_context(CCData *data);
    };

} }

#endif /* defined(__CCInstantAuth__) */
