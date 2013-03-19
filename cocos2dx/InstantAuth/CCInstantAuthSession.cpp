//
//  CCInstantAuthSession.cpp
//  InstantAuth
//
//  Created by Jeong YunWon on 13. 3. 19..
//
//  For cocos2d-x 2.x

#include "CCInstantAuthSession.h"

namespace cocos2d { namespace extension {

    CCHttpRequest *_qrequest(std::string& url, std::string& data) {
        CCHttpRequest *request = new CCHttpRequest::CCHttpRequest();
        request->setUrl(url.c_str());
        request->setRequestType(CCHttpRequest::kHttpPost);
        request->setRequestData(data.c_str(), data.length());
        return request;
    }

    CCHttpRequest *CCInstantAuthSession::_auth_request(std::string& url, void *data, cocos2d::CCString *session_key, cocos2d::CCObject *pTarget, SEL_CallFuncND pSelector) {
        CCData *ccdata = this->auth()->build_first_data(data, session_key);
        std::string sdata((const char *)ccdata->getBytes(), (const char *)ccdata->getBytes() + ccdata->getSize());

        CCHttpRequest *request = _qrequest(url, sdata);
        request->setResponseCallback(pTarget, pSelector);

        return request;
    }

    CCHttpRequest *CCInstantAuthSession::_reauth_request(void *data, cocos2d::CCObject *pTarget, SEL_CallFuncND pSelector) {
        CCData *ccdata = this->auth()->build_first_data(data, new CCString(this->_session_key.c_str()));
        std::string sdata((const char *)ccdata->getBytes(), (const char *)ccdata->getBytes() + ccdata->getSize());

        CCHttpRequest *request = _qrequest(this->_auth_url, sdata);
        request->setResponseCallback(pTarget, pSelector);

        return request;
    }

    CCHttpRequest *CCInstantAuthSession::_request(std::string& url, void *data, cocos2d::CCObject *pTarget, SEL_CallFuncND pSelector) {
        CCData *ccdata = this->auth()->build_data(data, this);
        std::string sdata((const char *)ccdata->getBytes(), (const char *)ccdata->getBytes() + ccdata->getSize());

        CCHttpRequest *request = _qrequest(url, sdata);
        new CCHttpRequest::CCHttpRequest();
        request->setResponseCallback(pTarget, pSelector);

        return request;
    }

} }
