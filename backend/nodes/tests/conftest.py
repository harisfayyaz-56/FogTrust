import pytest

from nodes.services import create_enrollment_token, enroll_node

from .helpers import new_keypair
from fogtrust_crypto.keys import sign_enrollment_proof


@pytest.fixture
def token_factory(db):
    """token, raw = token_factory(label="lab", minutes=15)"""

    def _make(label="lab 2", minutes=15):
        return create_enrollment_token(label=label, expires_in_minutes=minutes)

    return _make


@pytest.fixture
def node_factory(token_factory):
    """node, private_key = node_factory(name="gateway-01", capacity=4)  (enrolled through the real service)"""

    def _make(name="gateway-01", capacity=4):
        key, public = new_keypair()
        _, raw = token_factory(label=f"for {name}")
        node = enroll_node(
            raw_token=raw, name=name, public_key=public, capacity=capacity, proof=sign_enrollment_proof(key, raw, name)
        )
        return node, key

    return _make
