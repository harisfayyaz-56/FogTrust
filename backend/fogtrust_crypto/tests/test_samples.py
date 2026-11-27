"""The sample data is real: every committed case produces the outcome it claims, and no private key is in the files."""

import json
from pathlib import Path

import pytest

from fogtrust_crypto import samples

COMMITTED = Path(__file__).resolve().parents[3] / "docs" / "sample-data"


def test_freshly_generated_samples_all_behave_as_expected(tmp_path):
    samples.write(tmp_path)
    assert samples.check(tmp_path) == 0


@pytest.mark.skipif(not COMMITTED.exists(), reason="docs/sample-data is not in this checkout")
def test_the_committed_samples_still_behave_as_expected():
    assert samples.check(COMMITTED) == 0, "regenerate with: python -m fogtrust_crypto.samples --write ../docs/sample-data"


@pytest.mark.skipif(not COMMITTED.exists(), reason="docs/sample-data is not in this checkout")
def test_the_committed_files_contain_no_private_key_material():
    w = samples.world()
    secrets = [
        samples._seed("node-key").hex(), samples._seed("attacker-key").hex(), samples._seed("server-key").hex(),
    ]
    import base64

    secrets += [base64.b64encode(samples._seed(k)).decode() for k in ("node-key", "attacker-key", "server-key")]
    text = "".join((COMMITTED / n).read_text(encoding="utf-8") for n in ("heartbeats.json", "results.json"))
    assert all(s not in text for s in secrets)
    assert "-----BEGIN" not in text
    assert json.loads((COMMITTED / "heartbeats.json").read_text(encoding="utf-8"))["node"]["id"] == w["node_id"]


def test_every_failure_code_in_the_samples_is_a_real_code():
    from fogtrust_crypto import codes

    w = samples.world()
    known = set(codes.ALL_CODES) | {codes.OK}
    for data in (samples.build_heartbeats(w), samples.build_results(w)):
        assert {c["expected"]["reason_code"] for c in data["cases"]} <= known