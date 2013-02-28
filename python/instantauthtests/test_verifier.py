
import pytest

from instantauth.verifiers import BypassVerifier, DataKeyVerifier
from instantauth.verifiers.timehash import TimeHashVerifier

from instantauth.coders.json import JsonCoder

bypass = BypassVerifier('pubkey')
datakey = DataKeyVerifier(JsonCoder(), 'key')
timehash = TimeHashVerifier(now=lambda : 1000000000)

@pytest.mark.parametrize(('verifier', 'testcase'), [
    # mod       private_key public_key  input           output
    (bypass,  [('pvkey',    'pubkey',   'testdata',     'testdata')]),
    (datakey, [('pvkey',    'pubkey',   '{"key": "pubkey"}', '{"key": "pubkey"}')]), # need better test, not round-trip one
    (timehash,[('pvkey',    'pubkey',   'testdata',     'pubkey$3b9aca00f63f9ab09b4ea4b5e17e3fde03024c9d598e52ce$testdata')]),
])
def test_verifier(verifier, testcase, secret='SECRET'):
    """Round-trip test"""
    for private, public, input, expected_output in testcase:
        output = verifier.construct_data(input, private, public, secret)
        assert output == expected_output
        destructed = verifier.destruct_data(output, secret)
        assert destructed.public_key == public
        assert destructed.data == input
        test = verifier.verify(destructed, private, secret)
        assert test

