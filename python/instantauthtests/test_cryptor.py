
import pytest

from instantauth.cryptors import PlainCryptor
from instantauth.cryptors.aes import AESCryptor

plain = PlainCryptor()
aes = AESCryptor(256)

@pytest.mark.parametrize(('cryptor', 'testcase'), [
    (plain, {'test': {'global': 'test', 'data': 'test'}}),
    (aes, {'test': {}}),
])
def test_cryptor(cryptor, testcase, private_key='PRIVATE', secret='SECRET'):
    """Round-trip test"""
    for input, case in testcase.items():
        encrypted = cryptor.encrypt_global(input, secret)
        expected_global = case.get('global', None)
        if expected_global is not None:
            assert(expected_global == encrypted)
        decrypted = cryptor.decrypt_global(encrypted, secret)
        assert(decrypted == input)
        
        encrypted = cryptor.encrypt_data(input, private_key, secret)
        expected_data = case.get('data', None)
        if expected_data is not None:
            assert(expected_data == encrypted)
        decrypted = cryptor.decrypt_data(encrypted, private_key, secret)
        assert(decrypted == input)

