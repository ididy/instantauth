//
//  Base64Coder.cpp
//  InstantAuth
//
//  Created by Jeong YunWon on 13. 3. 25..
//
//

#include "Base64Coder.h"

namespace cocos2d { namespace extension { namespace instantauth {

    char Base64EncodingTable[65] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    void Base64EncodeData(const unsigned char *input, unsigned char *output) {
        output[0] = Base64EncodingTable[((input[0] & 0xfc) >> 2)];
        output[1] = Base64EncodingTable[((input[0] & 0x03) << 4) | ((input[1] & 0xf0) >> 4)];
        output[2] = Base64EncodingTable[((input[1] & 0x0f) << 2) | ((input[2] & 0xc0) >> 6)];
        output[3] = Base64EncodingTable[((input[2] & 0x3f)     )];
    }

    CCData *Base64Coder::encode(void *data) {
        CCData *idata = (CCData *)data;
        long inlen = idata->getSize();
        if (inlen == 0) {
            return 0;
        }
        long roughlen = (inlen * 4) / 3;
        long outlen = 4 * ((roughlen / 4) + ((roughlen % 4) != 0));
        unsigned char *outbuf = (unsigned char *)malloc(outlen + 1);
        outbuf[outlen] = 0;

        unsigned char *inpos = (unsigned char *)idata->getBytes();
        const unsigned char *inendian = inpos + inlen;

        unsigned char *outpos = outbuf;

        while (inendian - inpos >= 3) {
            Base64EncodeData(inpos, outpos);
            inpos += 3;
            outpos += 4;
        }

        long taillen = inendian - inpos;
        if (taillen) {
            unsigned char tailbuf[3];
            tailbuf[0] = inpos[0];
            tailbuf[1] = taillen == 2 ? inpos[1] : 0;
            tailbuf[2] = 0;
            Base64EncodeData(tailbuf, outpos);
            if (taillen != 2) {
                outpos[2] = '=';
            }
            outpos[3] = '=';
        }

        return new CCData(outbuf, outlen);
    }

} } }
