//
//  TimeHashVerifier.h
//  InstantAuth
//
//  Created by Jeong YunWon on 13. 3. 6..
//
//

#ifndef __InstantAuth__TimeHashVerifier__
#define __InstantAuth__TimeHashVerifier__

#include "CCInstantAuthProtocol.h"

namespace cocos2d { namespace extension { namespace instantauth {
    typedef time_t (*TimeFunc)(time_t *);

    class TimeHashVerifier: public Verifier {
        time_t limit_past;
        time_t limit_future;
        TimeFunc time_gen;
    public:
        TimeHashVerifier(time_t limit_past=120, time_t limit_future=300, TimeFunc now=&time) {
            this->limit_past = limit_past;
            this->limit_future = limit_future;
            this->time_gen = now;
        }
        virtual CCData *encode_verification(CCString *private_key, CCString *public_key, CCString *secret_key);
        virtual CCData *merge_verification_data(CCData *verification, CCData *data, CCString *secret_key);
    };

} } }

#endif /* defined(__InstantAuth__TimeHashVerifier__) */
