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
    char _Base64DecodingTable[0x80] = {
        //   0   1   2   3   4   5   6   7   8   9   a   b   c   d   e   f
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, // 0x10
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, // 0x20
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 62, -1, -1, -1, 63, // 0x30
        52, 53, 54, 55, 56, 57, 58, 59, 60, 61, -1, -1, -1, -1, -1, -1, // 0x40
        -1,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, // 0x50
        15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, -1, -1, -1, -1, -1, // 0x60
        -1, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, // 0x70
        41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, -1, -1, -1, -1, -1, // 0x80
    };
    unsigned char *Base64DecodingTable = (unsigned char *)_Base64DecodingTable;

    void Base64EncodeData(const unsigned char *input, unsigned char *output) {
        output[0] = Base64EncodingTable[((input[0] & 0xfc) >> 2)];
        output[1] = Base64EncodingTable[((input[0] & 0x03) << 4) | ((input[1] & 0xf0) >> 4)];
        output[2] = Base64EncodingTable[((input[1] & 0x0f) << 2) | ((input[2] & 0xc0) >> 6)];
        output[3] = Base64EncodingTable[((input[2] & 0x3f)     )];
    }

    void Base64DecodeData(const char *input, unsigned char *output) {
        unsigned char tmp1 = Base64DecodingTable[(int)input[0]];
        assert(tmp1 != 0xff);
        unsigned char tmp2 = Base64DecodingTable[(int)input[1]];
        assert(tmp2 != 0xff);
        output[0] = (char)(tmp1 << 2) | (tmp2 >> 4);
        tmp1 = Base64DecodingTable[(int)input[2]];
        assert(tmp1 != 0xff);
        output[1] = (char)(tmp2 << 4) | (tmp1 >> 2);
        tmp2 = Base64DecodingTable[(int)input[3]];
        assert(tmp2 != 0xff);
        output[2] = (char)(tmp1 << 6) | (tmp2);
    }


    CCData *Base64Coder::encode(void *data) {
        CCData *idata = (CCData *)data;
        long inlen = idata->getSize();
        if (inlen == 0) {
            return new CCData(0, 0);
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

    void *Base64Coder::decode(CCData *data) {
        unsigned long inlen = data->getSize();
        unsigned long datalen = inlen / 4 * 3;
        char *inpos = (char *)data->getBytes();
        unsigned long remain = inlen % 4;
        switch (remain) {
            case 0:
                if (inpos[inlen-2] == '=') {
                    inlen -= 2;
                    datalen -= 2;
                } else if (inpos[inlen-1] == '=') {
                    inlen -= 1;
                    datalen -= 1;
                }
                break;
            case 2:
                datalen += 1;
                break;
            case 3:
                datalen += 2;
                break;
            default:
                assert(0);
        }

        const char *inendian = inpos + inlen;

        unsigned char *buffer = (unsigned char *)malloc(datalen);
        unsigned char *outpos = buffer;

        while (inendian - inpos >= 4) {
            Base64DecodeData(inpos, outpos);
            inpos += 4;
            outpos += 3;
        }

        int taillen = inendian - inpos;
//        assert(taillen > 0);
        if (taillen) {
            unsigned char tmp1 = Base64DecodingTable[(int)inpos[0]];
            unsigned char tmp2 = Base64DecodingTable[(int)inpos[1]];
            outpos[0] = (unsigned char)(tmp1 << 2) + (tmp2 >> 4);
            if (taillen == 3) {
                tmp1 = Base64DecodingTable[(int)inpos[2]];
                outpos[1] = (unsigned char)(tmp2 << 4) + (tmp1 >> 2);
            }
        }

        return new CCData(buffer, datalen);
    }

} } }
