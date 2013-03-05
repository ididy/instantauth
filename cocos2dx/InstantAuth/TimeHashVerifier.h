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

    class TimeHashVerifier: public Verifier {
    public:
        virtual CCData *encode_verification(CCString *private_key, CCString *public_key, CCString *secret_key) {
            return 0;
        }
        virtual CCData *merge_verification_data(CCData *verification, CCData *data, CCString *secret_key) {
            return 0;
        }
    };

} } }

#endif /* defined(__InstantAuth__TimeHashVerifier__) */
