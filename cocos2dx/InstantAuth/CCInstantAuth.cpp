//
//  CCInstantAuth.cpp
//  InstantAuth
//
//  Created by Jeong YunWon on 13. 9. 5..
//
//

#include "CCInstantAuth.h"

namespace cocos2d { namespace extension {

    CCData *CCInstantAuth::build_data(void *data, void *session) {
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

    CCData *CCInstantAuth::build_first_data(void *data, CCString *session_key) {
        CCData *coded_data = this->datacoder->encode(data);
        assert(coded_data != NULL);
        CCData *encrypted_data = this->cryptor->encrypt_first_data(coded_data, this->secret_key);
        assert(encrypted_data != NULL);

        CCData *merged_data = this->verifier->construct_first_data(encrypted_data, session_key, secret_key);
        CCData *encrypted = this->cryptor->encrypt_stream(merged_data, this->secret_key);

        CCData *encoded_stream = this->streamcoder->encode(encrypted);
        return encoded_stream;
    }

    CCInstantAuthContext CCInstantAuth::get_context(CCData *data) {
        CCData *decoded_stream = (CCData *)this->streamcoder->decode(data);
        CCData *decrypted = this->cryptor->decrypt_stream(decoded_stream, this->secret_key);
        instantauth::VerifierDestructedData destructed = this->verifier->destruct_data(decrypted, this->secret_key);
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

    CCInstantAuthContext CCInstantAuth::get_first_context(CCData *data) {
        CCData *decoded_stream = (CCData *)this->streamcoder->decode(data);
        CCData *decrypted = this->cryptor->decrypt_stream(decoded_stream, this->secret_key);
        instantauth::VerifierDestructedData destructed = this->verifier->destruct_first_data(decrypted, this->secret_key);
        CCData *raw_data = this->cryptor->decrypt_first_data(destructed.data, this->secret_key);
        void *semantic_data = this->datacoder->decode(raw_data);

        CCInstantAuthContext context(NULL, semantic_data);
        destructed.destruct();
        return context;
    }
    
} }