#!/bin/bash
# Don't use git-submodule to keep upper trees clean
if [ ! -e cocos2d-x ]; then
    git clone git://github.com/cocos2d/cocos2d-x
fi
if [ ! -e rapidjson ]; then
    svn checkout http://rapidjson.googlecode.com/svn/trunk/ rapidjson
fi
if [ ! -e jsoncpp ]; then
    svn checkout https://jsoncpp.svn.sourceforge.net/svnroot/jsoncpp/trunk/jsoncpp/ jsoncpp
fi

