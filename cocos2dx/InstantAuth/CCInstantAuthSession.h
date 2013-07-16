//
//  CCInstantAuthSession.h
//  InstantAuth
//
//  Created by Jeong YunWon on 13. 3. 19..
//
//  For cocos2d-x 2.x

#include "CCInstantAuth.h"
#include "HttpRequest.h"

namespace cocos2d { namespace extension {

    class CCInstantAuthSession {
    protected:
        CCInstantAuth *_auth; // init on initializer
        std::string _session_key; // for auto-reauth
        std::string _auth_url; // for auto-reauth
        
        std::string _session_id;
        std::string _private_key;

        CCHttpRequest *_auth_request(std::string& url, void *data, cocos2d::CCString *session_key, cocos2d::CCObject *pTarget, SEL_HttpResponse pSelector);
        CCHttpRequest *_reauth_request(void *data, cocos2d::CCObject *pTarget, SEL_HttpResponse pSelector);
        CCHttpRequest *_request(std::string& url, void *data, cocos2d::CCObject *pTarget, SEL_HttpResponse pSelector);

    public:
        // Create constructor
        virtual ~CCInstantAuthSession() {
            delete this->_auth;
        }
        
        CCInstantAuth *auth() {
            return this->_auth;
        }

        CCString *cc_session_id() {
            return new CCString(this->_session_id.c_str());
        }

        CCString *cc_private_key() {
            return new CCString(this->_private_key.c_str());
        }
    };

} }
