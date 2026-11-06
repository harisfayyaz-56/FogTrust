import base64
import os
import stat

import pytest

from fogtrust_crypto.keys import (
    CryptoKeyError,
    generate_private_key,
    load_private_key,
    public_key_fingerprint,
    public_key_from_b64,
    public_key_to_b64,
    save_private_key,
    sign_enrollment_proof,
    verify_enrollment_proof,
)


def test_public_key_is_44_char_base64_of_32_bytes():
    b64 = public_key_to_b64(generate_private_key().public_key())
    assert len(b64) == 44
    assert len(base64.b64decode(b64)) == 32


def test_public_key_round_trip():
    pub = generate_private_key().public_key()
    assert public_key_to_b64(public_key_from_b64(public_key_to_b64(pub))) == public_key_to_b64(pub)


@pytest.mark.parametrize(
    "bad",
    [
        "",
        "short",
        "A" * 44,  # decodes to 33 bytes of padding problems / non-canonical
        "!" * 44,  # not base64
        base64.b64encode(b"x" * 31).decode(),  # wrong length
        base64.b64encode(b"x" * 33).decode(),
        " " + public_key_to_b64(generate_private_key().public_key())[:-1],  # whitespace
        None,
        12345,
    ],
)
def test_bad_public_keys_are_rejected(bad):
    with pytest.raises(CryptoKeyError):
        public_key_from_b64(bad)


def test_fingerprint_is_sha256_hex_and_accepts_b64():
    pub = generate_private_key().public_key()
    fp = public_key_fingerprint(pub)
    assert len(fp) == 64 and fp == public_key_fingerprint(public_key_to_b64(pub))


def test_keys_are_unique():
    assert public_key_to_b64(generate_private_key().public_key()) != public_key_to_b64(generate_private_key().public_key())


def test_save_and_load_private_key(tmp_path):
    key = generate_private_key()
    path = tmp_path / "keys" / "node.key"
    save_private_key(key, path)
    loaded = load_private_key(path)
    assert public_key_to_b64(loaded.public_key()) == public_key_to_b64(key.public_key())


@pytest.mark.skipif(os.name == "nt", reason="POSIX permission bits only")
def test_key_file_is_owner_only(tmp_path):
    path = tmp_path / "node.key"
    save_private_key(generate_private_key(), path)
    assert stat.S_IMODE(path.stat().st_mode) == 0o600


@pytest.mark.skipif(os.name == "nt", reason="POSIX permission bits only")
def test_load_refuses_group_or_world_readable_key(tmp_path):
    path = tmp_path / "node.key"
    save_private_key(generate_private_key(), path)
    path.chmod(0o644)
    with pytest.raises(CryptoKeyError, match="permissions"):
        load_private_key(path)


def test_save_refuses_to_overwrite(tmp_path):
    path = tmp_path / "node.key"
    save_private_key(generate_private_key(), path)
    with pytest.raises(CryptoKeyError, match="overwrite"):
        save_private_key(generate_private_key(), path)


def test_load_missing_file(tmp_path):
    with pytest.raises(CryptoKeyError):
        load_private_key(tmp_path / "nope.key")


def test_load_corrupt_file(tmp_path):
    path = tmp_path / "node.key"
    path.write_text("not a key\n")
    path.chmod(0o600)
    with pytest.raises(CryptoKeyError):
        load_private_key(path)


def test_error_messages_do_not_leak_key_material(tmp_path):
    key = generate_private_key()
    path = tmp_path / "node.key"
    save_private_key(key, path)
    secret = path.read_text().strip()
    with pytest.raises(CryptoKeyError) as caught:
        save_private_key(key, path)
    assert secret not in str(caught.value)


# ------------------------------------------------------- enrollment proof


def test_enrollment_proof_verifies():
    key = generate_private_key()
    proof = sign_enrollment_proof(key, "tok" * 10, "gateway-03")
    assert verify_enrollment_proof(public_key_to_b64(key.public_key()), "tok" * 10, "gateway-03", proof)


@pytest.mark.parametrize("token,name", [("other" * 6, "gateway-03"), ("tok" * 10, "gateway-04")])
def test_enrollment_proof_is_bound_to_token_and_name(token, name):
    key = generate_private_key()
    proof = sign_enrollment_proof(key, "tok" * 10, "gateway-03")
    assert not verify_enrollment_proof(public_key_to_b64(key.public_key()), token, name, proof)


def test_enrollment_proof_from_another_key_fails():
    key, other = generate_private_key(), generate_private_key()
    proof = sign_enrollment_proof(other, "tok" * 10, "gateway-03")
    assert not verify_enrollment_proof(public_key_to_b64(key.public_key()), "tok" * 10, "gateway-03", proof)


@pytest.mark.parametrize("junk", ["", "!!!", "QUJD", base64.b64encode(b"x" * 63).decode(), None])
def test_enrollment_proof_garbage_returns_false_not_exception(junk):
    pub = public_key_to_b64(generate_private_key().public_key())
    assert verify_enrollment_proof(pub, "t" * 20, "gateway-03", junk) is False


def test_enrollment_proof_bad_public_key_returns_false():
    assert verify_enrollment_proof("nope", "t" * 20, "gateway-03", "A" * 88) is False