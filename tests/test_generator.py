from canary.generator import CanaryGenerator, GeneratorError, rewrite_s3_url

CATS = {
    "product": {
        "templates": [
            "{codename} ships in {quarter}. Detail: {s3_url}",
            "{codename} slips; the {phrase} rework at {number} is the long pole. {s3_url}",
            "{codename} ({phrase}) committed for {quarter}. {s3_url}",
        ],
        "inverse_probe": ["What ships in {quarter}?"],
    }
}


def test_generate_is_reproducible_with_seed():
    g1 = CanaryGenerator(CATS, seed=42)
    g2 = CanaryGenerator(CATS, seed=42)
    c1, v1 = g1.generate("product", n_variants=3)
    c2, v2 = g2.generate("product", n_variants=3)
    assert c1.codename == c2.codename
    assert [v.text for v in v1] == [v.text for v in v2]


def test_codename_is_unique_and_shared_across_variants():
    g = CanaryGenerator(CATS, seed=1)
    canary, variants = g.generate("product", n_variants=3)
    # Codename appears in every variant (canary-level unique token).
    for v in variants:
        assert canary.codename in v.text
    assert canary.codename.startswith("Project ")


def test_variants_have_distinct_markers():
    g = CanaryGenerator(CATS, seed=7)
    _, variants = g.generate("product", n_variants=3)
    markers = [v.marker for v in variants]
    # Per-variant markers should differ (barium-meal traceability).
    assert len(set(markers)) == len(markers)


def test_audiences_are_assigned_in_order():
    g = CanaryGenerator(CATS, seed=3)
    _, variants = g.generate("product", n_variants=3, audiences=["team-a", "team-b"])
    assert variants[0].audience == "team-a"
    assert variants[1].audience == "team-b"
    assert variants[2].audience == "general"  # ran out of audiences


def test_unknown_category_raises():
    g = CanaryGenerator(CATS, seed=1)
    try:
        g.generate("nonexistent")
        assert False, "expected GeneratorError"
    except GeneratorError:
        pass


def test_inverse_probe_never_contains_codename():
    g = CanaryGenerator(CATS, seed=9)
    canary, _ = g.generate("product")
    probes = g.inverse_probes("product", canary.quarter)
    for p in probes:
        assert canary.codename not in p


def test_rewrite_s3_url_replaces_sentinel():
    g = CanaryGenerator(CATS, seed=2)
    canary, variants = g.generate("product")
    assert "<pending-honeytoken>" in canary.base_fact
    new = rewrite_s3_url(canary.base_fact, "s3://real-bucket/reports/x/y.pdf")
    assert "<pending-honeytoken>" not in new
    assert "s3://real-bucket/reports/x/y.pdf" in new
