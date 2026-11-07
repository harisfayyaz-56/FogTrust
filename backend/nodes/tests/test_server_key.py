"""The server's result-encryption key: configuration, enrollment response, system check, command. Threat ID-10."""

import os
import stat
from io import StringIO

import pytest
from django.core.management import call_command
from django.core.management.base import CommandError

from fogtrust_crypto.keys import generate_x25519_private_key, save_x25519_private_key, x25519_public_to_b64
from fogtrust_crypto.results import encrypt_result
from nodes import server_keys
from nodes.checks import check_result_key

from .helpers import ENROLL_URL, enroll_payload, post_json


@pytest.fixture
def key_file(tmp_path, settings):
    key = generate_x25519_private_key()
    path = tmp_path / "server_x25519.key"
    save_x25519_private_key(key, path)
    settings.RESULT_KEY_FILE = str(path)
    return key, path


@pytest.mark.django_db
class TestEnrollmentResponse:
    def test_the_public_key_is_returned_when_configured(self, api_client, token_factory, key_file):
        key, _ = key_file
        _, raw = token_factory()
        body = post_json(api_client, ENROLL_URL, enroll_payload(raw)).json()

        assert body["server_public_key"] == x25519_public_to_b64(key.public_key())

    def test_a_node_can_encrypt_to_the_returned_key_and_the_server_can_decrypt(self, api_client, token_factory, key_file):
        from fogtrust_crypto.results import decrypt_envelope

        _, raw = token_factory()
        body = post_json(api_client, ENROLL_URL, enroll_payload(raw)).json()
        task_id = "6f0e8c1e-7a4b-4f7c-9a3e-1c2d3e4f5a6b"
        envelope = encrypt_result(body["server_public_key"], body["node_id"], task_id, b'{"answer":42}')

        outcome = decrypt_envelope(server_keys.load_server_private_key(), body["node_id"], task_id, envelope)
        assert outcome.accepted and outcome.plaintext == b'{"answer":42}'

    def test_null_when_not_configured(self, api_client, token_factory, settings):
        settings.RESULT_KEY_FILE = ""
        _, raw = token_factory()
        assert post_json(api_client, ENROLL_URL, enroll_payload(raw)).json()["server_public_key"] is None

    def test_the_private_key_never_appears_in_any_response(self, api_client, token_factory, key_file):
        key, path = key_file
        _, raw = token_factory()
        response = post_json(api_client, ENROLL_URL, enroll_payload(raw))

        private_b64 = path.read_text().strip()
        assert private_b64 not in response.content.decode()


class TestSystemCheck:
    def test_warns_when_unset(self, settings):
        settings.RESULT_KEY_FILE = ""
        assert [m.id for m in check_result_key(None)] == ["nodes.W001"]

    def test_ok_when_valid(self, key_file):
        assert check_result_key(None) == []

    def test_only_a_warning_when_the_file_does_not_exist_yet(self, settings, tmp_path):
        settings.RESULT_KEY_FILE = str(tmp_path / "missing.key")
        assert [m.id for m in check_result_key(None)] == ["nodes.W002"]  # an error would block generate_server_key

    def test_management_commands_still_run_while_the_key_file_is_missing(self, settings, tmp_path):
        from django.core.management import call_command

        settings.RESULT_KEY_FILE = str(tmp_path / "missing.key")
        call_command("check")  # must not raise SystemCheckError

    @pytest.mark.skipif(os.name == "nt", reason="POSIX file modes")
    def test_error_when_the_file_is_readable_by_others(self, key_file):
        _, path = key_file
        path.chmod(0o644)
        assert [m.id for m in check_result_key(None)] == ["nodes.E002"]

    def test_error_when_the_file_is_garbage(self, settings, tmp_path):
        path = tmp_path / "bad.key"
        path.write_text("not a key\n")
        path.chmod(0o600)
        settings.RESULT_KEY_FILE = str(path)
        assert [m.id for m in check_result_key(None)] == ["nodes.E002"]


class TestGenerateServerKeyCommand:
    def test_creates_a_private_file_and_prints_the_public_key(self, tmp_path):
        out = StringIO()
        target = tmp_path / "keys" / "server.key"
        call_command("generate_server_key", out=str(target), stdout=out)

        assert target.exists()
        if os.name != "nt":
            assert stat.S_IMODE(target.stat().st_mode) == 0o600
        text = out.getvalue()
        assert "server_public_key:" in text and "FOGTRUST_RESULT_KEY_FILE=" in text
        assert target.read_text().strip() not in text  # the private key is never printed

    def test_refuses_to_overwrite_an_existing_key(self, tmp_path):
        target = tmp_path / "server.key"
        call_command("generate_server_key", out=str(target), stdout=StringIO())
        before = target.read_text()

        with pytest.raises(CommandError, match="refusing to overwrite"):
            call_command("generate_server_key", out=str(target), stdout=StringIO())
        assert target.read_text() == before


class TestCreateEnrollmentTokenCommand:
    @pytest.mark.django_db
    def test_prints_only_the_token_on_stdout_and_audits_it(self):
        from nodes.models import EnrollmentToken
        from nodes.services import hash_token
        from .helpers import last_audit

        out, err = StringIO(), StringIO()
        call_command("create_enrollment_token", label="demo node", minutes=5, stdout=out, stderr=err)

        raw = out.getvalue().strip()
        assert len(raw) >= 40 and " " not in raw
        assert EnrollmentToken.objects.get().token_hash == hash_token(raw)
        assert raw not in err.getvalue()
        event = last_audit("enroll.token_create", "success")
        assert (event.actor_type, event.actor_id) == ("system", "management-command")

    @pytest.mark.django_db
    @pytest.mark.parametrize("kwargs", [{"label": ""}, {"label": "x" * 65}, {"label": "a\nb"}, {"label": "ok", "minutes": 0}, {"label": "ok", "minutes": 99999}])
    def test_rejects_bad_arguments(self, kwargs):
        with pytest.raises(CommandError):
            call_command("create_enrollment_token", stdout=StringIO(), stderr=StringIO(), **kwargs)
