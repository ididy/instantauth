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
        
        CCData *build_data(void *data, void *session) {
            CCString *private_key = this->session_handler->get_private_key(session);

            CCData *coded_data = this->datacoder->encode(data);
            assert(coded_data != NULL);
            CCData *encrypted_data = this->cryptor->encrypt_data(coded_data, this->secret_key, private_key);
            assert(encrypted_data != NULL);

            CCString *public_key = this->session_handler->get_public_key(session);

            CCData *merged_data = this->verifier->construct_data(encrypted_data, private_key, public_key, secret_key);
            CCData *encrypted = this->cryptor->encrypt_stream(merged_data, this->secret_key);
            
            return this->streamcoder->encode(encrypted);
        }

        CCData *build_first_data(void *data, CCString *session_key) {
            CCData *coded_data = this->datacoder->encode(data);
            assert(coded_data != NULL);
            CCData *encrypted_data = this->cryptor->encrypt_first_data(coded_data, this->secret_key);
            assert(encrypted_data != NULL);
            
            CCData *merged_data = this->verifier->construct_first_data(encrypted_data, session_key, secret_key);
            CCData *encrypted = this->cryptor->encrypt_stream(merged_data, this->secret_key);
            
            return this->streamcoder->encode(encrypted);
        }

    };
    
} }

#endif /* defined(__CCInstantAuth__) */
