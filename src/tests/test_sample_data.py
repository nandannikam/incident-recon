import csv
from pathlib import Path

DATA_DIR = Path(__file__).resolve().parents[1] / "data"


def _read_rows(name: str) -> list[dict[str, str]]:
    with open(DATA_DIR / name, newline="") as f:
        return list(csv.DictReader(f))


def test_attack_sample_size_and_event_type_coverage() -> None:
    rows = _read_rows("attack_sample.csv")
    assert 15 <= len(rows) <= 20
    event_types = {r["event_type"] for r in rows}
    expected = {
        "process_execution",
        "file_download",
        "file_creation",
        "registry_modification",
        "network_connection",
        "powershell_execution",
        "log_deletion",
    }
    assert event_types == expected


def test_benign_sample_size_and_no_all_seven_types() -> None:
    rows = _read_rows("benign_sample.csv")
    assert len(rows) >= 10
    # benign data is intentionally NOT a full attack chain
    event_types = {r["event_type"] for r in rows}
    assert "log_deletion" not in event_types
