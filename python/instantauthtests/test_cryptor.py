
# -*- coding: utf-8 -*-
import pytest

from instantauth.cryptors import PlainCryptor
from instantauth.cryptors.aes import AESCryptor

from instantauth.coders.base64 import Base64Coder

plain = PlainCryptor()
aes = AESCryptor(256)

@pytest.mark.parametrize(('cryptor', 'testcase'), [
    (plain, {'test': {'global': 'test', 'data': 'test'}}),
    (aes, {'test': {'global': 'ZmD83NYDIuGOHae0lEXHdg=='}}),
    (aes, {'How about this long sentence, saying over-a-block size.': {'global': 'qmAGce5jfKOjCH9ZjqoOpJiFXSJqSqK7QvmUe3SJfzFF0TnSJKCM5OdOQeKO3D3QYupvFTQy60maRIRM+KBcsQ=='}}),
    (aes, {'한글 AES 인크립션': {'global': 'zAWE34okwAICmI9gMzx/kO1g0obxJqfU0UtkO0r+MPQ='}}),
])
def test_cryptor(cryptor, testcase, private_key='PRIVATE', secret='SECRET'):
    """Round-trip test"""
    b64coder = Base64Coder()
    for input, case in testcase.items():
        encrypted = cryptor.encrypt_global(input, secret)
        expected_global = case.get('global', None)
        if expected_global is not None:
            assert(expected_global == encrypted or expected_global == b64coder.encode(encrypted))
        decrypted = cryptor.decrypt_global(encrypted, secret)
        assert(decrypted == input)
        
        encrypted = cryptor.encrypt_data(input, private_key, secret)
        expected_data = case.get('data', None)
        if expected_data is not None:
            assert(expected_data == encrypted)
        decrypted = cryptor.decrypt_data(encrypted, private_key, secret)
        assert(decrypted == input)

