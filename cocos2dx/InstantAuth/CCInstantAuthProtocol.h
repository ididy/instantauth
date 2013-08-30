//
//  CCInstantAuthProtocol.h
//  InstantAuth
//
//  Created by Jeong YunWon on 13. 3. 6..
//
//

#ifndef __InstantAuth__CCAuthentication__
#define __InstantAuth__CCAuthentication__

#include "CCData.h"

namespace cocos2d { namespace extension {

class CCInstantAuthSession;
namespace instantauth {

    class Cryptor {
    public:
        virtual CCData *encrypt_stream(CCData *data, CCString *secret_key) = 0;
        virtual CCData *encrypt_data(CCData *data, CCString *private_key, CCString *secret_key) = 0;
        virtual CCData *encrypt_first_data(CCData *data, CCString *secret_key) {
            return this->encrypt_data(data, secret_key, secret_key);
        }

        virtual CCData *decrypt_stream(CCData *data, CCString *secret_key) = 0;
        virtual CCData *decrypt_data(CCData *data, CCString *private_key, CCString *secret_key) = 0;
        virtual CCData *decrypt_first_data(CCData *data, CCString *secret_key) {
            return this->decrypt_data(data, secret_key, secret_key);
        }
    };

    class VerifierDestructedData {
    public:
        CCString *public_key;
        CCString *verification;
        CCData *data;

        VerifierDestructedData(CCString *public_key, CCString *verification, CCData *data) {
            this->public_key = public_key;
            this->verification = verification;
            this->data = data;
        }
        
        void destruct() { // allow easy copying
            this->public_key->release();
            this->verification->release();
            this->data->release();
        }
    };

    class Verifier {
    public:
        virtual CCData *encode_verification(CCString *private_key, CCString *public_key, CCString *secret_key) = 0;
        virtual CCData *merge_verification_data(CCData *verification, CCData *data, CCString *secret_key) = 0;
        virtual CCData *construct_data(CCData *raw_data, CCString *private_key, CCString *public_key, CCString *secret_key) {
            CCData *verification = this->encode_verification(private_key, public_key, secret_key);
            CCData *data = this->merge_verification_data(verification, raw_data, secret_key);
            return data;
        }
        virtual CCData *construct_first_data(CCData *raw_data, CCString *session_key, CCString *secret_key) {
            return this->construct_data(raw_data, secret_key, session_key, secret_key);
        }

        virtual VerifierDestructedData divide_verification_and_data(CCData *raw_data, CCString *secret_key) = 0;
        virtual CCString *public_key_from_verification(CCString *verification, CCString *secret_key) = 0;
        virtual VerifierDestructedData destruct_data(CCData *raw_data, CCString *secret_key) {
            VerifierDestructedData vnd = this->divide_verification_and_data(raw_data, secret_key);
            CCString *public_key = this->public_key_from_verification(vnd.verification, secret_key);
            return VerifierDestructedData(public_key, vnd.verification, vnd.data);
        }
        virtual VerifierDestructedData destruct_first_data(CCData *raw_data, CCString *secret_key) {
            return this->destruct_data(raw_data, secret_key);
        }
        virtual bool verify(VerifierDestructedData destructed, CCString *private_key, CCString *secret_key) = 0;
    };

    class Coder {
    public:
        virtual CCData *encode(void *data) = 0;
        virtual void *decode(CCData *data) = 0;
    };

    class SessionHandler {
    public:
        virtual CCString *get_private_key(void *session) = 0;
        virtual CCString *get_public_key(void *session) = 0;
        virtual CCInstantAuthSession *get_session_from_public_key(CCString *public_key) = 0;
    };

    ///--- basic implementations

    class PlainCryptor: public Cryptor {
    public:
        virtual CCData *encrypt_data(CCData *data, CCString *private_key, CCString *secret_key) {
            return data;
        }
        virtual CCData *encrypt_stream(CCData *data, CCString *secret_key) {
            return data;
        }

        virtual CCData *decrypt_stream(CCData *data, CCString *secret_key) {
            return data;
        }
        virtual CCData *decrypt_data(CCData *data, CCString *private_key, CCString *secret_key) {
            return data;
        }
    };

    class BypassVerifier: public Verifier {
        CCString *_public_key;
    public:
        BypassVerifier(CCString *public_key) {
            this->_public_key = public_key;
        }
        ~BypassVerifier() {
            this->_public_key->release();
        }
        virtual CCData *encode_verification(CCString *private_key, CCString *public_key, CCString *secret_key) {
            return 0;
        }
        virtual CCData *merge_verification_data(CCData *verification, CCData *data, CCString *secret_key) {
            return data;
        }

        virtual VerifierDestructedData divide_verification_and_data(CCData *raw_data, CCString *secret_key) {
            return VerifierDestructedData(NULL, NULL, raw_data);
        }
        virtual CCString *public_key_from_verification(CCString *verification, CCString *secret_key) {
            return this->_public_key;
        }
        virtual bool verify(VerifierDestructedData destructed, CCString *private_key, CCString *secret_key) {
            return true;
        }
    };

    class DataKeyVerifier: public Verifier {
    protected:
        Coder *_coder;
        CCObject *_key;
    public:
        DataKeyVerifier(Coder *coder, CCObject *key) {
            this->_coder = coder;
            this->_key = key;
        }
        virtual ~DataKeyVerifier() {
            this->_key->release();
        }
        virtual CCData *encode_verification(CCString *private_key, CCString *public_key, CCString *secret_key) {
            assert(0);
            return 0;
        }
        virtual CCData *merge_verification_data(CCData *verification, CCData *data, CCString *secret_key) {
            assert(0);
            return NULL;
        }

        virtual VerifierDestructedData divide_verification_and_data(CCData *raw_data, CCString *secret_key) {
            assert(0);
            return VerifierDestructedData(NULL, NULL, NULL);
        }
        virtual CCString *public_key_from_verification(CCString *verification, CCString *secret_key) {
            assert(0);
            return NULL;
        }
        virtual bool verify(VerifierDestructedData destructed, CCString *private_key, CCString *secret_key) {
            return destructed.verification && destructed.verification->getCString() && destructed.verification->length();
        }
    };

    /**
     *  @brief Special coder for coder-embedded verifier
     */
    class PlainCoder: public Coder {
    public:
        virtual CCData *encode(void *data) {
            return (CCData *)data;
        }

        virtual void *decode(CCData *data) {
            return (void *)data;
        }
    };

} } }

#endif
