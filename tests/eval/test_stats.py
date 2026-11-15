from vision.eval.stats import family_bypass_rate, rule_of_three, wilson


def test_wilson_interval():
    lo, hi = wilson(85, 100)
    assert 0.76 <= lo <= 0.80
    assert 0.90 <= hi <= 0.92
    assert wilson(0, 0) == (0.0, 0.0)


def test_rule_of_three():
    assert rule_of_three(300) == 0.01
    assert rule_of_three(0) == 1.0


def test_family_bypass_rate():
    rows = [
        {"label": "malicious", "family_id": "f1", "outcome": "AST_BLOCKED"},
        {"label": "malicious", "family_id": "f1", "outcome": "SANDBOX_CONTAINED"},
        {"label": "malicious", "family_id": "f2", "outcome": "AST_BLOCKED"},
    ]
    byp, tot, rate = family_bypass_rate(rows)
    assert (byp, tot, rate) == (1, 2, 0.5)
