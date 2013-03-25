
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

@pytest.mark.parametrize(('cryptor', 'verifier', 'coder', 'sessionhandler'), combinations)
def test_authentication(cryptor, verifier, coder, sessionhandler, secret='SECRET'):
    """Round-trip test"""
    authentication = Authentication(PlainCoder(), cryptor, verifier, coder, sessionhandler, secret)
    i = {'f1':'v1'}
    
    d = authentication.build_first_data(i, '1')
    c = authentication.get_first_context(d)
    
    assert i == c.data
    
    d = authentication.build_data(i, c.session)
    c = authentication.get_context(d)
    
    assert i == c.data

