//
//  CCInstantAuthProtocol.h
//  InstantAuth
//
//  Created by Jeong YunWon on 13. 3. 6..
//
//

#ifndef __InstantAuth__CCAuthentication__
#define __InstantAuth__CCAuthentication__

namespace cocos2d { namespace extension { namespace instantauth {

    class Cryptor {
    public:
        virtual CCData *encrypt_stream(CCData *data, CCString *secret_key) = 0;
        virtual CCData *encrypt_data(CCData *data, CCString *private_key, CCString *secret_key) = 0;
        virtual CCData *encrypt_first_data(CCData *data, CCString *secret_key) {
            return this->encrypt_data(data, secret_key, secret_key);
        }

        /*
        virtual CCData *decrypt(CCData *data, CCString *secret_key) = 0;
        virtual CCData *decrypt_data(CCData *data, CCString *secret_key, CCString *private_key) = 0;
        virtual CCData *decrypt_first_data(CCData *data, CCString *secret_key) {
            return this->decrypt_data(data, secret_key, secret_key);
        }
        */
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
    };

    class Coder {
    public:
        virtual CCData *encode(void *data) = 0;
    };

    class SessionHandler {
    public:
        virtual CCString *get_private_key(void *session) = 0;
        virtual CCString *get_public_key(void *session) = 0;
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
    };

    class BypassVerifier: public Verifier {
    public:
        virtual CCData *encode_verification(CCString *private_key, CCString *public_key, CCString *secret_key) {
            return 0;
        }
        virtual CCData *merge_verification_data(CCData *verification, CCData *data, CCString *secret_key) {
            return data;
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
            delete this->_key;
        }
        virtual CCData *encode_verification(CCString *private_key, CCString *public_key, CCString *secret_key) {
            assert(0);
            return 0;
        }
        virtual CCData *merge_verification_data(CCData *verification, CCData *data, CCString *secret_key) {
            assert(0);
            return NULL;
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
    };

} } }

#endif
