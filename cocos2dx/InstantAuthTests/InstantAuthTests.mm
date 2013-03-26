//
//  InstantAuthTests.m
//  InstantAuthTests
//
//  Created by Jeong YunWon on 13. 3. 5..
//
//

#import "InstantAuthTests.h"

#import "CCInstantAuth.h"
#import "CCInstantAuthSession.h"
#import "AESCryptor.h"
#import "TimeHashVerifier.h"
#import "RapidJsonCoder.h"
#import "Base64Coder.h"

#include <rapidjson/document.h>

#include <string.h>

using namespace cocos2d::extension;
using namespace cocos2d::extension::instantauth;

class TestSession: public CCInstantAuthSession {
public:
    CCString *public_key;
    CCString *private_key;
};

class TestSessionHandler: public SessionHandler {
public:
    virtual CCString *get_private_key(void *session) {
        TestSession *sess = (TestSession *)session;
        return sess->private_key;
    }
    virtual CCString *get_public_key(void *session) {
        TestSession *sess = (TestSession *)session;
        return sess->public_key;
    }
};


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
    Base64Coder base64Coder;

    PlainCryptor plainCryptor;
    AES256Cryptor aesCryptor;

    BypassVerifier bypassVerifier;

    PlainCoder plainCoder;

    RapidJsonCoder rapidJsonCoder;
    RapidJsonDataKeyVerifier *rapidJsonDataKeyVerifier = new RapidJsonDataKeyVerifier(&rapidJsonCoder, new CCString("key"));

    TimeHashVerifier timehashVerifier;
}

- (void)testAESCryptor {
    Coder *base64 = new Base64Coder();

    unsigned char *input = (unsigned char *)"test";
    Cryptor *cryptor = new AES256Cryptor();
    CCData *inputData = new CCData(input, strlen((const char*)input));
    CCData *result = cryptor->encrypt_stream(inputData, new CCString("SECRET"));
    result = base64->encode((void *)result);
    const char *result_bytes = (const char *)result->getBytes();
    const char *expected = "ZmD83NYDIuGOHae0lEXHdg==";
    STAssertEquals(strncmp(expected, result_bytes, strlen(expected)), 0, @"expected: %s / found: %s", expected, result_bytes);

    result = cryptor->encrypt_data(inputData, new CCString(""), new CCString("SECRET"));
    result = base64->encode((void *)result);
    result_bytes = (const char *)result->getBytes();
    STAssertEquals(strncmp(expected, result_bytes, strlen(expected)), 0, @"expected: %s / found: %s", expected, result_bytes);

    result = cryptor->encrypt_data(inputData, new CCString("PRIVATE"), new CCString("SECRET"));
    result = base64->encode((void *)result);
    result_bytes = (const char *)result->getBytes();
    expected = "8QFEX+ESikvs2vvzfe09jw==";
    STAssertEquals(strncmp(expected, result_bytes, strlen(expected)), 0, @"expected: %s / found: %s", expected, result_bytes);
}

- (void)testAESCryptorLong {
    Coder *base64 = new Base64Coder();

    unsigned char *input = (unsigned char *)"How about this long sentence, saying over-a-block size.";
    Cryptor *cryptor = new AES256Cryptor();
    CCData *result = cryptor->encrypt_stream(new CCData(input, strlen((const char *)input)), new CCString("SECRET"));
    result = base64->encode((void *)result);
    const char *result_bytes = (const char *)result->getBytes();
    const char *expected = "qmAGce5jfKOjCH9ZjqoOpJiFXSJqSqK7QvmUe3SJfzFF0TnSJKCM5OdOQeKO3D3QYupvFTQy60maRIRM+KBcsQ==";
    STAssertEquals(strncmp(expected, result_bytes, strlen(expected)), 0, @"");
}

- (void)testAESCryptorHangul {
    Coder *base64 = new Base64Coder();

    unsigned char *input = (unsigned char *)"한글 AES 인크립션";
    Cryptor *cryptor = new AES256Cryptor();
    CCData *result = cryptor->encrypt_stream(new CCData(input, strlen((const char*)input)), new CCString("SECRET"));
    result = base64->encode((void *)result);
    const char *result_bytes = (const char *)result->getBytes();
    const char *expected = "zAWE34okwAICmI9gMzx/kO1g0obxJqfU0UtkO0r+MPQ=";
    STAssertEquals(strncmp(expected, result_bytes, strlen(expected)), 0, @"");
}

time_t ctime(time_t*) { return 1000000000; }

- (void)testTimeHashVerifier {
    TimeHashVerifier *timehashVerifier = new TimeHashVerifier(120, 300, &ctime);
    CCData *data = timehashVerifier->construct_data(new CCData((unsigned char *)"testdata", 8), new CCString("pvkey"), new CCString("pubkey"), new CCString("SECRET"));
    const char *output = (const char *)data->getBytes();
    const char *solution = "pubkey$3b9aca00f63f9ab09b4ea4b5e17e3fde03024c9d598e52ce$testdata";
    STAssertEquals(strncmp(output, solution, strlen(solution)), 0, @"expected: %s / found: %s", solution, output);
}

- (void)testTimeHashJson {
    PlainCoder streamcoder;
    PlainCryptor cryptor;
    TimeHashVerifier timehashVerifier(120, 300, &ctime);
    RapidJsonCoder rapidJsonCoder;
    TestSessionHandler handler;
    CCString secret("SECRET");

    CCInstantAuth auth(&streamcoder, &cryptor, &timehashVerifier, &rapidJsonCoder, &handler, &secret);

    rapidjson::Document doc;
    rapidjson::Value value(rapidjson::kObjectType);
    value.AddMember("field", "value", doc.GetAllocator());

    CCData *data = auth.build_first_data(&value, new CCString("v"));

    const char *output = (const char *)data->getBytes();
    const char *expected = "v$3b9aca008d34b0ce271d8d499ed4f44678db1175ae547b95${\"field\":\"value\"}";
    STAssertEquals(strncmp(expected, output, strlen(expected)), 0, @"expected: %s / found: %s", expected, output);
}

- (void)testAESTimeHashJson {
    Base64Coder base64coder;
    AES256Cryptor aesCryptor;
    TimeHashVerifier timehashVerifier(120, 300, &ctime);
    RapidJsonCoder rapidJsonCoder;
    TestSessionHandler handler;
    CCString secret("SECRET");

    CCInstantAuth auth(&base64coder, &aesCryptor, &timehashVerifier, &rapidJsonCoder, &handler, &secret);

    rapidjson::Document doc;
    rapidjson::Value value(rapidjson::kObjectType);
    value.AddMember("field", "value", doc.GetAllocator());

    CCData *data = auth.build_first_data(&value, new CCString("v"));

    const char *output = (const char *)data->getBytes();
    const char *expected = "wJ8UaQ0+pQm3V9Rpj+ZnmS9K9vFi9G5Lrr5Mv7oS/PvgxZSSKmu02Had5Z4CQ5AgpMR3qJ6GFshPRAjIB5v/B3eP6ILSDlyjrcgA51wlzzrVEi5uAQPHB9X742xD11lR";
    STAssertEquals(strncmp(expected, output, strlen(expected)), 0, @"expected: %s / found: %s", expected, output);
}

@end
