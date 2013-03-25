//
//  InstantAuthTests.m
//  InstantAuthTests
//
//  Created by Jeong YunWon on 13. 3. 5..
//
//

#import "InstantAuthTests.h"

#import "CCInstantAuth.h"
#import "AESCryptor.h"
#import "TimeHashVerifier.h"
#import "RapidJsonCoder.h"
#import "Base64Coder.h"

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

- (void)testCpp
{
    const char text[] = "Hello, World";
    std::string v(text, text + strlen(text));
    STAssertEquals(v.size(), strlen(text), @"");

    const unsigned char data[] = "Hello, World!";
    std::string x(data, data + strlen((const char *)data));
    STAssertEquals(x.size(), strlen((const char *)data), @"");
}

- (void)testCreations
{
    PlainCryptor *plainCryptor = new PlainCryptor();
    AESCryptor *aesCryptor = new AESCryptor();

    BypassVerifier *bypassVerifier = new BypassVerifier();

    PlainCoder *plainCoder = new PlainCoder();
    RapidJsonCoder *rapidJsonCoder = new RapidJsonCoder();
    RapidJsonDataKeyVerifier *rapidJsonDataKeyVerifier = new RapidJsonDataKeyVerifier(rapidJsonCoder, new CCString("key"));

    TimeHashVerifier *timehashVerifier = new TimeHashVerifier();
}

- (void)testAESCryptor {
    Base64Coder *base64 = new Base64Coder();

    unsigned char *input = (unsigned char *)"test";
    AESCryptor *cryptor = new AESCryptor();
    CCData *result = cryptor->encrypt(new CCData(input, 4), new CCString("SECRET"));
    result = base64->encode((void *)result);
    const char *result_bytes = (const char *)result->getBytes();
    STAssertEquals(strcmp(result_bytes, "ZmD83NYDIuGOHae0lEXHdg=="), 0, @"");
}

- (void)testTimeHashVerifier {
    TimeHashVerifier *timehashVerifier = new TimeHashVerifier();
    CCData *data = timehashVerifier->construct_data(new CCData((unsigned char *)"testdata", 8), new CCString("pvkey"), new CCString("pubkey"), new CCString("SECRET"));
    const char *output = (const char *)data->getBytes();
    const char *solution = "pubkey$3b9aca00f63f9ab09b4ea4b5e17e3fde03024c9d598e52ce$testdata";
    strncmp(output, solution, strlen(solution));
}

@end
