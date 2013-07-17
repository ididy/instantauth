//
//  Base64Coder.h
//  InstantAuth
//
//  Created by Jeong YunWon on 13. 3. 25..
//
//

#ifndef __InstantAuth__Base64Coder__
#define __InstantAuth__Base64Coder__

#include "CCInstantAuthProtocol.h"

namespace cocos2d { namespace extension { namespace instantauth {

    class Base64Coder: public Coder {
    public:
        virtual CCData *encode(void *data);
        virtual void *decode(CCData *data);
    };
    
} } }

#endif /* defined(__InstantAuth__Base64Coder__) */
