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
#import "TimeHashVerifier.h"

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

    TimeHashVerifier *timehashVerifier = new TimeHashVerifier();
}

- (void)testTimeHashVerifier {
    TimeHashVerifier *timehashVerifier = new TimeHashVerifier();
    CCData *data = timehashVerifier->construct_data(new CCData((unsigned char *)"testdata", 8), new CCString("pvkey"), new CCString("pubkey"), new CCString("SECRET"));
    const char *output = (const char *)data->getBytes();
    const char *solution = "pubkey$3b9aca00f63f9ab09b4ea4b5e17e3fde03024c9d598e52ce$testdata";
    strncmp(output, solution, strlen(solution));
}

@end
