from canary.fuzzy import find_matches, score_token


def test_exact_codename_match():
    text = "I heard Project Zephyrine is shipping soon."
    matches = find_matches(text, codename="Project Zephyrine", threshold=82)
    assert any(m.kind == "codename" for m in matches)


def test_codename_without_prefix_still_matches():
    text = "Apparently Zephyrine is the new sync engine."
    matches = find_matches(text, codename="Project Zephyrine", threshold=82)
    assert any(m.kind == "codename" for m in matches)


def test_paraphrased_phrase_matches_via_token_set():
    # Word order changed - token_set_ratio should still catch it.
    text = "the lattice amber component was reworked last quarter"
    matches = find_matches(text, markers=["amber lattice"], threshold=82)
    assert any(m.kind == "phrase" for m in matches)


def test_number_matches_despite_formatting():
    text = "revenue came in around 47318902 dollars"
    matches = find_matches(text, markers=["47,318,902.00 | amber lattice"], threshold=82)
    assert any(m.kind == "number" for m in matches)


def test_no_false_positive_on_unrelated_text():
    text = "The weather today is sunny with a chance of rain."
    matches = find_matches(
        text, codename="Project Zephyrine",
        markers=["47,318,902.00 | amber lattice"], threshold=82,
    )
    assert matches == []


def test_score_token_number_digit_stream():
    assert score_token("1,234.56", "number", "value was 123456 units") == 100.0
