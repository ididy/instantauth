
import pytest

from instantauth.cryptors import PlainCryptor
from instantauth.cryptors.aes import AESCryptor

from instantauth.coders.base64 import Base64Coder

plain = PlainCryptor()
aes = AESCryptor(256)

@pytest.mark.parametrize(('cryptor', 'testcase'), [
    (plain, {'test': {'global': 'test', 'data': 'test'}}),
    (aes, {'test': {'global': 'rL5QWh1u1DPB5S96LQV9qtgawlpTcBYO5VsTWhIWbfI='}}),
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

