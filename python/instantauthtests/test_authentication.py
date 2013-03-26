
import pytest
import itertools

from instantauth.cryptors import PlainCryptor
from instantauth.cryptors.aes import AESCryptor

plain = PlainCryptor()
aes = AESCryptor(256)

cryptors = [plain, aes]

from instantauth.coders import ConstantCoder, PlainCoder
from instantauth.coders.urlquery import URLQueryCoder, SimpleURLQueryCoder
from instantauth.coders.json import JsonCoder

surlquery = SimpleURLQueryCoder()
json = JsonCoder()

coders = [surlquery, json]

from instantauth.verifiers import BypassVerifier
from instantauth.verifiers.timehash import TimeHashVerifier

bypass = BypassVerifier('1')
timehash = TimeHashVerifier(now=lambda : 1000000000)

verifiers = [bypass, timehash]

from session import TestSessionHandler

handler1 = TestSessionHandler()
handlers = [handler1]

combinations = [list(combination) for combination in itertools.product(cryptors, verifiers, coders, handlers)]
from instantauth import Authentication

from instantauth.coders.base64 import Base64Coder

@pytest.mark.parametrize(('cryptor', 'verifier', 'coder', 'sessionhandler'), combinations)
def test_authentication(cryptor, verifier, coder, sessionhandler, secret='SECRET'):
    """Round-trip test"""
    authentication = Authentication(Base64Coder(), cryptor, verifier, coder, sessionhandler, secret)
    i = {'f1':'v1'}
    
    d = authentication.build_first_data(i, '1')
    c = authentication.get_first_context(d)
    
    assert i == c.data
    
    d = authentication.build_data(i, c.session)
    c = authentication.get_context(d)
    
    assert i == c.data

def test_aes_timehash_json():
    data = {'field': 'value'}
    auth = Authentication(Base64Coder(), AESCryptor(256), TimeHashVerifier(now=lambda: 1000000000), JsonCoder(), handler1, 'SECRET')

    d = auth.build_first_data(data, 'v')
    print d
    assert d == 'wJ8UaQ0+pQm3V9Rpj+ZnmS9K9vFi9G5Lrr5Mv7oS/PvgxZSSKmu02Had5Z4CQ5AgpMR3qJ6GFshPRAjIB5v/B3eP6ILSDlyjrcgA51wlzzrVEi5uAQPHB9X742xD11lR'
    
    c = auth.get_first_context(d)
    assert data == c.data
