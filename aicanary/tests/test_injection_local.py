from canary.injection import get_adapter
from canary.injection.local_docstore import LocalDocStoreAdapter
from canary.models import Canary, Variant


def _canary_and_variants():
    canary = Canary(
        canary_id="can_x", category="product", codename="Project Zephyrine",
        base_fact="Project Zephyrine ships in Q3.", quarter="Q3",
        s3_url="s3://b/reports/can_x/abc.pdf",
    )
    variants = [
        Variant(variant_id="var_1", canary_id="can_x",
                text="Project Zephyrine ships in Q3.", marker="1013 | amber lattice",
                audience="team-a"),
        Variant(variant_id="var_2", canary_id="can_x",
                text="Project Zephyrine slips to Q4.", marker="2024 | cobalt harbor",
                audience="team-b"),
    ]
    return canary, variants


def test_adapter_is_registered():
    assert get_adapter("local_docstore") is LocalDocStoreAdapter


def test_plant_writes_one_file_per_variant(tmp_path):
    canary, variants = _canary_and_variants()
    adapter = LocalDocStoreAdapter({"name": "local", "root": str(tmp_path / "docs")})
    results = adapter.plant(canary, variants)
    assert len(results) == 2
    for r in results:
        from pathlib import Path
        p = Path(r.location)
        assert p.exists()
        content = p.read_text()
        assert "Project Zephyrine" in content


def test_to_plants_creates_records(tmp_path):
    canary, variants = _canary_and_variants()
    adapter = LocalDocStoreAdapter({"name": "local", "root": str(tmp_path / "docs")})
    results = adapter.plant(canary, variants)
    plants = adapter.to_plants(canary, results)
    assert len(plants) == 2
    assert all(p.canary_id == "can_x" for p in plants)
    assert all(p.target_system == "local" for p in plants)
