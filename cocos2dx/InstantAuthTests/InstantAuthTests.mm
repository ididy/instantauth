//
//  InstantAuthTests.m
//  InstantAuthTests
//
//  Created by Jeong YunWon on 13. 3. 5..
//
//

#import "InstantAuthTests.h"

#import "CCInstantAuth.h"
#import "RapidJsonCoder.h"

@implementation InstantAuthTests

- (void)setUp
{
    [super setUp];
    
    // Set-up code here.
}

- (void)tearDown
{
    // Tear-down code here.
    
    [super tearDown];
}

using namespace cocos2d::extension;
using namespace cocos2d::extension::instantauth;

- (void)testCreations
{
    PlainCryptor *plainCryptor = new PlainCryptor();

    BypassVerifier *bypassVerifier = new BypassVerifier();

    PlainCoder *plainCoder = new PlainCoder();
    RapidJsonCoder *rapidJsonCoder = new RapidJsonCoder();
    RapidJsonDataKeyVerifier *rapidJsonDataKeyVerifier = new RapidJsonDataKeyVerifier(rapidJsonCoder, new CCString("key"));
}

@end
