
import json as json_mod
import pytest

from instantauth.coders import ConstantCoder, PlainCoder
from instantauth.coders.urlquery import URLQueryCoder, SimpleURLQueryCoder
from instantauth.coders.json import JsonCoder

constant = ConstantCoder('encode', 'decode')
plain = PlainCoder()
surlquery = SimpleURLQueryCoder()
json = JsonCoder()

@pytest.mark.parametrize(('coder', 'testcase'), [
    (constant, [('decode', 'encode')]),
    (plain, [('foo', 'foo')]),
    (surlquery, [({'f1': 'v1', 'f2': 'v2'}, 'f1=v1&f2=v2')]),
    (json, [({'f1': 'v1', 'i': None}, json_mod.dumps({'f1': 'v1', 'i': None}, separators=(',',':')))]),
])
def test_coder(coder, testcase, secret='SECRET'):
    """Round-trip test"""
    for case in testcase:
        input = case[0]
        if len(case) == 1:
            expected = None
        elif len(case) == 2:
            expected = case[1]
        else:
            raise Exception

        encoded = coder.encode(input)
        if expected is not None:
            assert expected == encoded
        decoded = coder.decode(encoded)
        assert input == decoded

