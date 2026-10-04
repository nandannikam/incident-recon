"""Phase 3, Step 4 — host / IP / hash normalisation."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from app.dispatch import parse_any_log
from app.models import Event, EventType
from app.normalize import (
    extract_hashes,
    normalize_event,
    normalize_events,
    normalize_host,
    normalize_ip,
)

SHA256 = "a" * 64
MD5 = "b" * 32
SHA1 = "c" * 40


def _event(
    event_type: str = "process_execution",
    *,
    source: str = "HOST01",
    target: str = "x.exe",
    metadata: dict | None = None,
) -> Event:
    return Event(
        event_id="e:0",
        timestamp=datetime(2024, 1, 1, tzinfo=UTC),
        source=source,
        event_type=EventType(event_type),
        actor="USER01",
        target=target,
        metadata=metadata or {},
    )


# ---------------------------------------------------------------------------
# Hosts
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "raw, expected",
    [
        ("SCRANTON.dmevals.local", "scranton"),
        ("scranton", "scranton"),
        (" Scranton. ", "scranton"),
        ("WIN-ABC123.corp.local", "win-abc123"),
        ("HOST01", "host01"),
        ("192.168.1.5", "192.168.1.5"),
        ("::1", "::1"),
    ],
)
def test_normalize_host(raw: str, expected: str) -> None:
    assert normalize_host(raw) == expected


@pytest.mark.parametrize("raw", [None, "", "   ", "-", "N/A", "unknown", "."])
def test_normalize_host_returns_none_for_placeholders(raw: object) -> None:
    assert normalize_host(raw) is None


def test_different_spellings_of_one_host_normalise_equal() -> None:
    spellings = ["NASHUA.dmevals.local", "nashua", "Nashua.", "NASHUA.DMEVALS.LOCAL."]

    assert len({normalize_host(s) for s in spellings}) == 1


# ---------------------------------------------------------------------------
# IPs
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "raw, expected",
    [
        ("185.220.101.1", "185.220.101.1"),
        (" 185.220.101.1 ", "185.220.101.1"),
        ("010.001.001.001", "10.1.1.1"),
        ("::ffff:10.0.0.1", "10.0.0.1"),
        ("[2001:DB8::1]", "2001:db8::1"),
        ("2001:0db8:0000:0000:0000:0000:0000:0001", "2001:db8::1"),
        ("fe80::1%eth0", "fe80::1"),
    ],
)
def test_normalize_ip(raw: str, expected: str) -> None:
    assert normalize_ip(raw) == expected


@pytest.mark.parametrize(
    "raw", [None, "", "-", "999.1.1.1", "1.2.3", "not-an-ip", "1.2.3.4.5", 12345]
)
def test_normalize_ip_rejects_non_addresses(raw: object) -> None:
    assert normalize_ip(raw) is None


# ---------------------------------------------------------------------------
# Hashes
# ---------------------------------------------------------------------------


def test_extract_hashes_parses_a_sysmon_hash_string() -> None:
    text = f"SHA1={SHA1},MD5={MD5},SHA256={SHA256.upper()},IMPHASH={'d' * 32}"

    assert extract_hashes(text) == {
        "sha1": SHA1,
        "md5": MD5,
        "sha256": SHA256,  # lower-cased
        "imphash": "d" * 32,
    }


@pytest.mark.parametrize(
    "text",
    [
        None,
        "",
        "-",
        "SHA256=tooshort",
        f"SHA256={'g' * 64}",  # right length, not hex
        f"CRC32={'a' * 8}",  # unknown algorithm
        "no-equals-sign",
    ],
)
def test_extract_hashes_drops_corrupt_or_unknown_entries(text: object) -> None:
    assert extract_hashes(text) == {}


def test_extract_hashes_keeps_valid_entries_next_to_invalid_ones() -> None:
    assert extract_hashes(f"MD5=bad,SHA256={SHA256}") == {"sha256": SHA256}


# ---------------------------------------------------------------------------
# Events
# ---------------------------------------------------------------------------


def test_normalize_event_adds_host_ip_and_hashes_without_touching_anything_else() -> None:
    event = _event(
        "network_connection",
        source="SCRANTON.dmevals.local",
        target="185.220.101.1",
        metadata={"Hashes": f"SHA256={SHA256}", "DestinationPort": 443},
    )

    normalize_event(event)

    assert event.metadata["_host_norm"] == "scranton"
    assert event.metadata["_ip_norm"] == "185.220.101.1"
    assert event.metadata["_hashes"] == {"sha256": SHA256}
    # originals untouched
    assert event.source == "SCRANTON.dmevals.local"
    assert event.target == "185.220.101.1"
    assert event.metadata["Hashes"] == f"SHA256={SHA256}"
    assert event.metadata["DestinationPort"] == 443


def test_ip_is_taken_from_destination_ip_metadata_for_any_event_type() -> None:
    event = _event(metadata={"DestinationIp": "010.000.000.009"})

    assert normalize_event(event).metadata["_ip_norm"] == "10.0.0.9"


def test_non_network_event_target_is_not_mistaken_for_an_ip() -> None:
    assert "_ip_norm" not in normalize_event(_event(target="10.0.0.1")).metadata


def test_missing_values_add_no_keys() -> None:
    event = normalize_event(_event(source="-"))

    assert event.metadata == {}


def test_normalisation_is_idempotent() -> None:
    event = _event(
        "network_connection",
        source="H.corp.local",
        target="::ffff:1.2.3.4",
        metadata={"Hashes": f"MD5={MD5}"},
    )

    first = dict(normalize_event(event).metadata)
    second = dict(normalize_event(event).metadata)

    assert first == second


def test_normalize_events_handles_many_and_returns_a_list() -> None:
    events = [_event(source=f"HOST{i}.lab") for i in range(3)]

    result = normalize_events(iter(events))

    assert [e.metadata["_host_norm"] for e in result] == ["host0", "host1", "host2"]


# ---------------------------------------------------------------------------
# Wired into the pipeline entry point
# ---------------------------------------------------------------------------


def test_parse_any_log_normalises_csv_events(tmp_path: Path) -> None:
    path = tmp_path / "a.csv"
    path.write_text(
        "timestamp,source,event_type,actor,target,metadata\n"
        '2024-01-01T10:00:00Z,SCRANTON.dmevals.local,network_connection,p.exe,010.001.001.001,"{}"\n',
        encoding="utf-8",
    )

    event = parse_any_log(path).events[0]

    assert event.metadata["_host_norm"] == "scranton"
    assert event.metadata["_ip_norm"] == "10.1.1.1"
    assert event.source == "SCRANTON.dmevals.local"  # raw value kept


def test_parse_any_log_normalises_mordor_events(tmp_path: Path) -> None:
    line = json.dumps(
        {
            "SourceName": "Microsoft-Windows-Sysmon",
            "Hostname": "NASHUA.dmevals.local",
            "TimeCreated": "2020-09-15 03:30:10.500",
            "EventID": 3,
            "Message": (
                "Network connection detected:\n"
                "Image: C:\\Windows\\System32\\cmd.exe\n"
                "DestinationIp: ::ffff:185.220.101.1\n"
                "User: LAB\\user01\n"
            ),
        }
    )
    path = tmp_path / "mordor.json"
    path.write_text(line + "\n", encoding="utf-8")

    event = parse_any_log(path).events[0]

    assert event.metadata["_host_norm"] == "nashua"
    assert event.metadata["_ip_norm"] == "185.220.101.1"


def test_hashes_are_extracted_from_real_sysmon_data() -> None:
    data_dir = Path(__file__).resolve().parents[1] / "data" / "mordor"
    candidates = sorted(data_dir.glob("*bitsadmin*.json"))
    if not candidates:
        pytest.skip("bitsadmin Mordor dataset not downloaded")

    events = parse_any_log(candidates[0]).events
    hashed = [e for e in events if "_hashes" in e.metadata]

    assert hashed, "expected Sysmon process events with a Hashes field"
    for event in hashed:
        for algorithm, digest in event.metadata["_hashes"].items():
            assert digest == digest.lower()
            assert len(digest) in (32, 40, 64), algorithm
