from canary.models import Canary, Variant, Plant, S3Hit, ProbeHit
from canary.store import Store


def _mk_store(tmp_path):
    return Store(tmp_path / "test.db")


def _mk_canary(cid="can_1"):
    return Canary(
        canary_id=cid, category="product", codename="Project Zephyrine",
        base_fact="Project Zephyrine ships in Q3.", quarter="Q3",
        s3_bucket="b", s3_key="reports/can_1/abc.pdf", s3_url="s3://b/reports/can_1/abc.pdf",
    )


def test_add_and_get_canary(tmp_path):
    s = _mk_store(tmp_path)
    c = _mk_canary()
    s.add_canary(c)
    got = s.get_canary("can_1")
    assert got is not None
    assert got.codename == "Project Zephyrine"


def test_find_canary_by_key(tmp_path):
    s = _mk_store(tmp_path)
    s.add_canary(_mk_canary())
    got = s.find_canary_by_key("reports/can_1/abc.pdf")
    assert got and got.canary_id == "can_1"


def test_status_transitions(tmp_path):
    s = _mk_store(tmp_path)
    s.add_canary(_mk_canary())
    s.set_canary_status("can_1", "planted")
    assert s.get_canary("can_1").status == "planted"


def test_invalid_status_rejected(tmp_path):
    s = _mk_store(tmp_path)
    s.add_canary(_mk_canary())
    try:
        s.set_canary_status("can_1", "bogus")
        assert False
    except ValueError:
        pass


def test_variants_and_plants(tmp_path):
    s = _mk_store(tmp_path)
    s.add_canary(_mk_canary())
    s.add_variant(Variant(variant_id="var_1", canary_id="can_1",
                          text="t", marker="1 | amber lattice", audience="team-a"))
    s.add_plant(Plant(plant_id="pl_1", canary_id="can_1", variant_id="var_1",
                     target_system="local_docstore", location="/tmp/x.md"))
    assert len(s.list_variants("can_1")) == 1
    assert len(s.list_plants("can_1")) == 1


def test_s3_hit_dedupe(tmp_path):
    s = _mk_store(tmp_path)
    s.add_canary(_mk_canary())
    h = S3Hit(hit_id="h1", canary_id="can_1", s3_bucket="b",
              s3_key="reports/can_1/abc.pdf", event_name="GetObject",
              source_ip="1.2.3.4", user_agent="curl", event_time="2026-01-01T00:00:00Z")
    assert s.add_s3_hit(h) is True
    assert s.add_s3_hit(h) is False  # idempotent
    assert len(s.list_s3_hits("can_1")) == 1


def test_probe_hit(tmp_path):
    s = _mk_store(tmp_path)
    s.add_canary(_mk_canary())
    s.add_probe_hit(ProbeHit(hit_id="ph1", canary_id="can_1", tool="copilot",
                            probe_kind="inverse_question", matched_token="Zephyrine",
                            match_score=95.0, response_text="..."))
    assert len(s.list_probe_hits("can_1")) == 1
