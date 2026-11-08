"""The measurement script doubles as a regression test: detection must stay complete."""

from fogtrust_crypto.measure import build_report


def test_quick_measurement_finds_no_false_positives_or_negatives():
    report, summary = build_report(quick=True)
    assert summary["false_positives"] == 0 and summary["honest_total"] > 0
    assert summary["false_negatives"] == 0 and summary["attack_total"] > 0
    assert summary["wrong_reason"] == 0  # every attack was rejected for the reason it should be
    assert summary["replay_accepted"] == 0
    for heading in ("## D1.", "## D2.", "## D3.", "## C3."):
        assert heading in report