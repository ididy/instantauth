#!/bin/bash
# Don't use git-submodule to keep upper trees clean
if [ ! -e cocos2d-x ]; then
    git clone git://github.com/cocos2d/cocos2d-x
fi
if [ ! -e rapidjson ]; then
    svn checkout http://rapidjson.googlecode.com/svn/trunk/ rapidjson
fi
if [ ! -e openssl ]; then
    git clone git://git.openssl.org/openssl.git
fi