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

        CCData *build_data(void *data, void *session) {
            CCString *private_key = this->session_handler->get_private_key(session);

            CCData *coded_data = this->datacoder->encode(data);
            assert(coded_data != NULL);
            CCData *encrypted_data = this->cryptor->encrypt_data(coded_data, private_key, this->secret_key);
            assert(encrypted_data != NULL);

            CCString *public_key = this->session_handler->get_public_key(session);

            CCData *merged_data = this->verifier->construct_data(encrypted_data, private_key, public_key, this->secret_key);
            CCData *encrypted = this->cryptor->encrypt_stream(merged_data, this->secret_key);

            CCData *encoded_stream = this->streamcoder->encode(encrypted);
            return encoded_stream;
        }

        CCData *build_first_data(void *data, CCString *session_key) {
            CCData *coded_data = this->datacoder->encode(data);
            assert(coded_data != NULL);
            CCData *encrypted_data = this->cryptor->encrypt_first_data(coded_data, this->secret_key);
            assert(encrypted_data != NULL);

            CCData *merged_data = this->verifier->construct_first_data(encrypted_data, session_key, secret_key);
            CCData *encrypted = this->cryptor->encrypt_stream(merged_data, this->secret_key);

            CCData *encoded_stream = this->streamcoder->encode(encrypted);
            return encoded_stream;
        }

        CCInstantAuthContext get_context(CCData *data) {
            CCData *decoded_stream = (CCData *)this->streamcoder->decode(data);
            CCData *decrypted = this->cryptor->decrypt_stream(decoded_stream, this->secret_key);
            instantauth::VerifierDestructedData destructed = this->verifier->destruct_first_data(decrypted, this->secret_key);
            if (!destructed.public_key) {
                assert(0);
            }
            CCInstantAuthSession *session = this->session_handler->get_session_from_public_key(destructed.public_key);
            CCString *private_key = this->session_handler->get_private_key(session);
            CCData *raw_data = this->cryptor->decrypt_data(destructed.data, private_key, this->secret_key);
            void *semantic_data = this->datacoder->decode(raw_data);
            if (!this->verifier->verify(destructed, private_key, this->secret_key)) {
                assert(0);
            }
            CCInstantAuthContext context(session, semantic_data);
            destructed.destruct();
            return context;
        }

        CCInstantAuthContext get_first_context(CCData *data) {
            CCData *decoded_stream = (CCData *)this->streamcoder->decode(data);
            CCData *decrypted = this->cryptor->decrypt_stream(decoded_stream, this->secret_key);
            instantauth::VerifierDestructedData destructed = this->verifier->destruct_first_data(decrypted, this->secret_key);
            CCData *raw_data = this->cryptor->decrypt_first_data(destructed.data, this->secret_key);
            void *semantic_data = this->datacoder->decode(raw_data);

            CCInstantAuthContext context(NULL, semantic_data);
            destructed.destruct();
            return context;
        }
    };

} }

#endif /* defined(__CCInstantAuth__) */
