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
#import "JsonCppCoder.h"
#import "Base64Coder.h"

#include <rapidjson/document.h>
#include <json/value.h>

#include <string.h>

using namespace cocos2d::extension;
using namespace cocos2d::extension::instantauth;

class TestSession: public CCInstantAuthSession {
public:
    CCString *public_key;
    CCString *private_key;
};

class TestSessionHandler: public SessionHandler {
    TestSession *_session;
public:
    TestSessionHandler(TestSession *session) {
        this->_session = session;
    }
    virtual CCString *get_private_key(void *session) {
        TestSession *sess = (TestSession *)session;
        return sess->private_key;
    }
    virtual CCString *get_public_key(void *session) {
        TestSession *sess = (TestSession *)session;
        return sess->public_key;
    }
    virtual CCInstantAuthSession *get_session_from_public_key(CCString *public_key) {
        return this->_session;
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

    BypassVerifier bypassVerifier(new CCString("pkey"));

    PlainCoder plainCoder;

    RapidJsonCoder rapidJsonCoder;
    JsonCppCoder jsonCppCoder;
    RapidJsonDataKeyVerifier *rapidJsonDataKeyVerifier = new RapidJsonDataKeyVerifier(&rapidJsonCoder, new CCString("key"));
    JsonCppDataKeyVerifier *jsonDataKeyVerifier = new JsonCppDataKeyVerifier(&jsonCppCoder, new CCString("key"));

    TimeHashVerifier timehashVerifier;
}

- (void)testAESCryptor {
    Coder *base64 = new Base64Coder();
    CCString *secret = new CCString("SECRET");

    unsigned char *input = (unsigned char *)"test";
    Cryptor *cryptor = new AES256Cryptor();
    CCData *inputData = new CCData(input, strlen((const char*)input));
    CCData *result = cryptor->encrypt_stream(inputData, secret);
    CCData *coded_result = base64->encode((void *)result);
    CCData *decoded_result = (CCData *)base64->decode(coded_result);
    STAssertEquals(result->getSize(), decoded_result->getSize(), @"");
    STAssertEquals(strncmp((char *)result->getBytes(), (char *)decoded_result->getBytes(), result->getSize()), 0, @"");

    const char *result_bytes = (const char *)coded_result->getBytes();
    const char *expected = "ZmD83NYDIuGOHae0lEXHdg==";
    STAssertEquals(strncmp(expected, result_bytes, strlen(expected)), 0, @"expected: %s / found: %s", expected, result_bytes);
    CCData *roundtrip = cryptor->decrypt_stream(result, secret);
    STAssertEquals(inputData->getSize(), roundtrip->getSize(), @"");
    STAssertEquals(strncmp((char *)inputData->getBytes(), (char *)roundtrip->getBytes(), inputData->getSize()), 0, @"");

    result = cryptor->encrypt_data(inputData, new CCString(""), secret);
    coded_result = base64->encode((void *)result);
    result_bytes = (const char *)coded_result->getBytes();
    STAssertEquals(strncmp(expected, result_bytes, strlen(expected)), 0, @"expected: %s / found: %s", expected, result_bytes);
    roundtrip = cryptor->decrypt_data(result, new CCString(""), secret);
    STAssertEquals(inputData->getSize(), roundtrip->getSize(), @"");
    STAssertEquals(strncmp((char *)inputData->getBytes(), (char *)roundtrip->getBytes(), inputData->getSize()), 0, @"");

    result = cryptor->encrypt_data(inputData, new CCString("PRIVATE"), secret);
    coded_result = base64->encode((void *)result);
    result_bytes = (const char *)coded_result->getBytes();
    expected = "8QFEX+ESikvs2vvzfe09jw==";
    STAssertEquals(strncmp(expected, result_bytes, strlen(expected)), 0, @"expected: %s / found: %s", expected, result_bytes);
    roundtrip = cryptor->decrypt_data(result, new CCString("PRIVATE"), secret);
    STAssertEquals(inputData->getSize(), roundtrip->getSize(), @"");
    STAssertEquals(strncmp((char *)inputData->getBytes(), (char *)roundtrip->getBytes(), inputData->getSize()), 0, @"");
}

- (void)testAESCryptorLong {
    Coder *base64 = new Base64Coder();
    CCString *secret = new CCString("SECRET");

    unsigned char *input = (unsigned char *)"How about this long sentence, saying over-a-block size.";
    CCData *inputData = new CCData(input, strlen((const char *)input));
    Cryptor *cryptor = new AES256Cryptor();
    CCData *result = cryptor->encrypt_stream(inputData, secret);
    CCData *coded_result = base64->encode((void *)result);
    const char *result_bytes = (const char *)coded_result->getBytes();
    const char *expected = "qmAGce5jfKOjCH9ZjqoOpJiFXSJqSqK7QvmUe3SJfzFF0TnSJKCM5OdOQeKO3D3QYupvFTQy60maRIRM+KBcsQ==";
    STAssertEquals(strncmp(expected, result_bytes, strlen(expected)), 0, @"");
    CCData *roundtrip = cryptor->decrypt_stream(result, secret);
    STAssertEquals(inputData->getSize(), roundtrip->getSize(), @"");
    STAssertEquals(strncmp((char *)inputData->getBytes(), (char *)roundtrip->getBytes(), inputData->getSize()), 0, @"");
}

- (void)testAESCryptorHangul {
    Coder *base64 = new Base64Coder();
    CCString *secret = new CCString("SECRET");

    unsigned char *input = (unsigned char *)"한글 AES 인크립션";
    CCData *inputData = new CCData(input, strlen((const char *)input));
    Cryptor *cryptor = new AES256Cryptor();
    CCData *result = cryptor->encrypt_stream(inputData, secret);
    CCData *coded_result = base64->encode((void *)result);
    const char *result_bytes = (const char *)coded_result->getBytes();
    const char *expected = "zAWE34okwAICmI9gMzx/kO1g0obxJqfU0UtkO0r+MPQ=";
    STAssertEquals(strncmp(expected, result_bytes, strlen(expected)), 0, @"");
    CCData *roundtrip = cryptor->decrypt_stream(result, secret);
    STAssertEquals(inputData->getSize(), roundtrip->getSize(), @"");
    STAssertEquals(strncmp((char *)inputData->getBytes(), (char *)roundtrip->getBytes(), inputData->getSize()), 0, @"");
}

time_t ctime(time_t*) { return 1000000000; }

- (void)testTimeHashVerifier {
    CCString *secret = new CCString("SECRET");
    TimeHashVerifier *timehashVerifier = new TimeHashVerifier(120, 300, &ctime);
    CCData *inputData = new CCData((unsigned char *)"testdata", 8);
    CCData *data = timehashVerifier->construct_data(inputData, new CCString("pvkey"), new CCString("pubkey"), secret);
    const char *output = (const char *)data->getBytes();
    const char *solution = "pubkey$3b9aca00f63f9ab09b4ea4b5e17e3fde03024c9d598e52ce$testdata";
    STAssertEquals(strncmp(output, solution, strlen(solution)), 0, @"expected: %s / found: %s", solution, output);
    VerifierDestructedData destructedData = timehashVerifier->destruct_data(data, secret);
    CCData *roundtrip = destructedData.data;
    STAssertEquals(inputData->getSize(), roundtrip->getSize(), @"");
    STAssertEquals(strncmp((char *)inputData->getBytes(), (char *)roundtrip->getBytes(), inputData->getSize()), 0, @"");
}

- (void)testTimeHashJson {
    PlainCoder streamcoder;
    PlainCryptor cryptor;
    TimeHashVerifier timehashVerifier(120, 300, &ctime);
    RapidJsonCoder rapidJsonCoder;
    TestSession *session = new TestSession();
    session->public_key = new CCString("v");
    session->private_key = new CCString("pv");
    TestSessionHandler handler(session);
    CCString secret("SECRET");

    CCInstantAuth auth(&streamcoder, &cryptor, &timehashVerifier, &rapidJsonCoder, &handler, &secret);

    rapidjson::Document doc;
    rapidjson::Value value(rapidjson::kObjectType);
    value.AddMember("field", "value", doc.GetAllocator());

    CCData *data = auth.build_first_data(&value, new CCString("v"));

    const char *output = (const char *)data->getBytes();
    const char *expected = "v$3b9aca008d34b0ce271d8d499ed4f44678db1175ae547b95${\"field\":\"value\"}";
    STAssertEquals(strncmp(expected, output, strlen(expected)), 0, @"expected: %s / found: %s", expected, output);

    CCInstantAuthContext context = auth.get_first_context(data);
    rapidjson::Document *_roundtrip = (rapidjson::Document *)context.data;
    rapidjson::Document& roundtrip = *_roundtrip;
    STAssertEquals(strcmp(roundtrip["field"].GetString(), value["field"].GetString()), 0, @"");

    data = auth.build_data(&value, session);

    output = (const char *)data->getBytes();
    expected = "v$3b9aca00741e96c093a4a5c230d3ea592adcabf3e055df4a${\"field\":\"value\"}";
    STAssertEquals(strncmp(expected, output, strlen(expected)), 0, @"expected: %s / found: %s", expected, output);

    context = auth.get_context(data);
    _roundtrip = (rapidjson::Document *)context.data;
    rapidjson::Document& roundtrip2 = *_roundtrip;
    STAssertEquals(strcmp(roundtrip2["field"].GetString(), value["field"].GetString()), 0, @"");
}

- (void)testTimeHashJsonCpp {
    PlainCoder streamcoder;
    PlainCryptor cryptor;
    TimeHashVerifier timehashVerifier(120, 300, &ctime);
    JsonCppCoder jsonCppCoder;
    TestSession *session = new TestSession();
    session->public_key = new CCString("v");
    session->private_key = new CCString("pv");
    TestSessionHandler handler(session);
    CCString secret("SECRET");

    CCInstantAuth auth(&streamcoder, &cryptor, &timehashVerifier, &jsonCppCoder, &handler, &secret);

    Json::Value value;
    value["field"] = "value";

    CCData *data = auth.build_first_data(&value, new CCString("v"));

    const char *output = (const char *)data->getBytes();
    const char *expected = "v$3b9aca008d34b0ce271d8d499ed4f44678db1175ae547b95${\"field\":\"value\"}";
    STAssertEquals(strncmp(expected, output, strlen(expected)), 0, @"expected: %s / found: %s", expected, output);

    CCInstantAuthContext context = auth.get_first_context(data);

    Json::Value *_roundtrip = (Json::Value *)context.data;
    Json::Value& roundtrip = *_roundtrip;
    STAssertEquals(roundtrip["field"].asString() == value["field"].asString(), true, @"");

    data = auth.build_data(&value, session);

    output = (const char *)data->getBytes();
    expected = "v$3b9aca00741e96c093a4a5c230d3ea592adcabf3e055df4a${\"field\":\"value\"}";
    STAssertEquals(strncmp(expected, output, strlen(expected)), 0, @"expected: %s / found: %s", expected, output);

    context = auth.get_context(data);
    _roundtrip = (Json::Value *)context.data;
    Json::Value& roundtrip2 = *_roundtrip;
    STAssertEquals(roundtrip2["field"].asString() == value["field"].asString(), true, @"");
}


- (void)testAESTimeHashJson {
    Base64Coder base64coder;
    AES256Cryptor aesCryptor;
    TimeHashVerifier timehashVerifier(120, 300, &ctime);
    RapidJsonCoder rapidJsonCoder;
    TestSession *session = new TestSession();
    session->public_key = new CCString("v");
    session->private_key = new CCString("pv");
    TestSessionHandler handler(session);
    CCString secret("SECRET");

    CCInstantAuth auth(&base64coder, &aesCryptor, &timehashVerifier, &rapidJsonCoder, &handler, &secret);

    rapidjson::Document doc;
    rapidjson::Value value(rapidjson::kObjectType);
    value.AddMember("field", "value", doc.GetAllocator());

    CCData *data = auth.build_first_data(&value, new CCString("v"));

    const char *output = (const char *)data->getBytes();
    const char *expected = "wJ8UaQ0+pQm3V9Rpj+ZnmS9K9vFi9G5Lrr5Mv7oS/PvgxZSSKmu02Had5Z4CQ5AgpMR3qJ6GFshPRAjIB5v/B3eP6ILSDlyjrcgA51wlzzrVEi5uAQPHB9X742xD11lR";
    STAssertEquals(strlen(expected), data->getSize(), @"expected: %s / found: %s", expected, output);
    STAssertEquals(strncmp(expected, output, strlen(expected)), 0, @"expected: %s / found: %s", expected, output);

    CCInstantAuthContext context = auth.get_first_context(data);
    rapidjson::Document *_roundtrip = (rapidjson::Document *)context.data;
    rapidjson::Document& roundtrip = *_roundtrip;
    STAssertEquals(strcmp(roundtrip["field"].GetString(), value["field"].GetString()), 0, @"");

    data = auth.build_data(&value, session);

    output = (const char *)data->getBytes();
    expected = "sTZkvpTfADtge51D9Mwprs8zSzmHAx8PDk/VoX6+pI+Gb47o393wxShTdlJV4oT26XE6sBwcNXPzWkR+I9wuiD/9lBUKo8LLiZbNBiCvWhYTpeIN45aZDUXWVDijMFMH";
    STAssertEquals(strncmp(expected, output, strlen(expected)), 0, @"expected: %s / found: %s", expected, output);

    context = auth.get_context(data);
    _roundtrip = (rapidjson::Document *)context.data;
    rapidjson::Document& roundtrip2 = *_roundtrip;
    STAssertEquals(strcmp(roundtrip2["field"].GetString(), value["field"].GetString()), 0, @"");
}

- (void)testAESTimeHashJsonCpp {
    Base64Coder base64coder;
    AES256Cryptor aesCryptor;
    TimeHashVerifier timehashVerifier(120, 300, &ctime);
    JsonCppCoder jsonCoder;
    TestSession *session = new TestSession();
    session->public_key = new CCString("v");
    session->private_key = new CCString("pv");
    TestSessionHandler handler(session);
    CCString secret("SECRET");

    CCInstantAuth auth(&base64coder, &aesCryptor, &timehashVerifier, &jsonCoder, &handler, &secret);

    Json::Value value;
    value["field"] = "value";
    STAssertEquals(value["field"].asString() == "value", true, @"");
    CCData *data = auth.build_first_data(&value, new CCString("v"));

    const char *output = (const char *)data->getBytes();
    const char *expected = "wJ8UaQ0+pQm3V9Rpj+ZnmS9K9vFi9G5Lrr5Mv7oS/PvgxZSSKmu02Had5Z4CQ5AgpMR3qJ6GFshPRAjIB5v/B3eP6ILSDlyjrcgA51wlzzrVEi5uAQPHB9X742xD11lR";
    STAssertEquals(strlen(expected), data->getSize(), @"expected: %s / found: %s", expected, output);
    STAssertEquals(strncmp(expected, output, strlen(expected)), 0, @"expected: %s / found: %s", expected, output);

    CCInstantAuthContext context = auth.get_first_context(data);
    Json::Value *_roundtrip = (Json::Value *)context.data;
    Json::Value& roundtrip = *_roundtrip;
    STAssertEquals(roundtrip["field"].asString() == value["field"].asString(), true, @"");

    data = auth.build_data(&value, session);

    output = (const char *)data->getBytes();
    expected = "sTZkvpTfADtge51D9Mwprs8zSzmHAx8PDk/VoX6+pI+Gb47o393wxShTdlJV4oT26XE6sBwcNXPzWkR+I9wuiD/9lBUKo8LLiZbNBiCvWhYTpeIN45aZDUXWVDijMFMH";
    STAssertEquals(strncmp(expected, output, strlen(expected)), 0, @"expected: %s / found: %s", expected, output);

    context = auth.get_context(data);
    _roundtrip = (Json::Value *)context.data;
    Json::Value& roundtrip2 = *_roundtrip;
    STAssertEquals(roundtrip2["field"].asString() == value["field"].asString(), true, @"");
}

@end
