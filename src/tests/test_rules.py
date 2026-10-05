"""Step 6 tests — Knowledge Base (rules)."""

from datetime import UTC, datetime
from pathlib import Path

from app.graph import build_graph
from app.models import Conclusion, Event, EventType
from app.rules.registry import (
    RULES,
    detect_log_deletion,
    detect_network_beacon,
    detect_persistence_established,
    detect_powershell_staging,
    detect_registry_persistence,
)

DATA_DIR = Path(__file__).resolve().parents[1] / "data"

# A real T1547.001 autostart location, so REG-PERSIST-01 tests that target
# time/host/order logic are not accidentally failing the key allowlist.
AUTOSTART_KEY = r"HKLM\Software\Microsoft\Windows\CurrentVersion\Run\Updater"
NON_AUTOSTART_KEY = r"HKLM\Software\SomeApp\Settings"


def _event(
    event_id: str,
    timestamp: str,
    *,
    event_type: str,
    actor: str = "USER01",
    source: str = "HOST01",
    target: str | None = None,
    metadata: dict | None = None,
) -> Event:
    return Event(
        event_id=event_id,
        timestamp=datetime.fromisoformat(timestamp).astimezone(UTC),
        source=source,
        event_type=EventType(event_type),
        actor=actor,
        target=target if target is not None else event_id,
        metadata=metadata or {},
    )


def _parsed(name: str) -> list[Event]:
    from app.parser import parse_log

    return parse_log(str(DATA_DIR / name)).events


def _attack_events() -> list[Event]:
    return _parsed("attack_sample.csv")


def _benign_events() -> list[Event]:
    return _parsed("benign_sample.csv")


def _staging_conclusion(events: list[Event]) -> Conclusion:
    staging = detect_powershell_staging(events, build_graph(events), [])
    assert staging is not None
    return staging


def test_registry_contains_the_three_demo_rules() -> None:
    assert RULES == [
        detect_registry_persistence,
        detect_powershell_staging,
        detect_persistence_established,
        detect_network_beacon,
        detect_log_deletion,
    ]


def test_reg_persist_fires_on_attack_neighborhood() -> None:
    attack = _attack_events()
    proc = next(e for e in attack if e.target == "invoice.exe")
    reg = next(
        e
        for e in attack
        if e.target == r"HKLM:\Software\Microsoft\Windows\CurrentVersion\Run\Updater"
    )

    conclusion = detect_registry_persistence([proc, reg], build_graph(attack), [])

    assert conclusion is not None
    assert conclusion.rule_id == "REG-PERSIST-01"
    assert conclusion.technique_id == "T1547.001"
    assert conclusion.tactic == "Persistence"
    assert conclusion.evidence[0].event_ids == [proc.event_id, reg.event_id]
    assert conclusion.evidence[0].parent_conclusion_id is None


def test_reg_persist_requires_execution_before_modification() -> None:
    reg = _event(
        "r",
        "2024-01-01T10:01:00Z",
        event_type="registry_modification",
        target=AUTOSTART_KEY,
    )
    proc = _event("p", "2024-01-01T10:02:00Z", event_type="process_execution")

    assert (
        detect_registry_persistence([proc, reg], build_graph([proc, reg]), []) is None
    )


def test_reg_persist_returns_none_outside_time_window() -> None:
    proc = _event("p", "2024-01-01T10:00:00Z", event_type="process_execution")
    reg = _event(
        "r",
        "2024-01-01T10:06:00Z",
        event_type="registry_modification",  # 6 min later
        target=AUTOSTART_KEY,
    )

    assert (
        detect_registry_persistence([proc, reg], build_graph([proc, reg]), []) is None
    )


def test_reg_persist_window_boundary_is_inclusive() -> None:
    # Matching writer images so this exercises the strongest (writer-matched)
    # path while still testing the inclusive 5-minute boundary.
    proc = _event(
        "p",
        "2024-01-01T10:00:00Z",
        event_type="process_execution",
        metadata={"Image": r"C:\Windows\System32\Updater.EXE"},
    )
    reg = _event(
        "r",
        "2024-01-01T10:05:00Z",
        event_type="registry_modification",  # exactly 5 min
        target=AUTOSTART_KEY,
        metadata={"Image": r"c:\windows\system32\updater.exe"},
    )

    conclusion = detect_registry_persistence([proc, reg], build_graph([proc, reg]), [])

    assert conclusion is not None
    assert conclusion.confidence == 0.6


def test_reg_persist_ignores_non_autostart_key() -> None:
    proc = _event("p", "2024-01-01T10:00:00Z", event_type="process_execution")
    reg = _event(
        "r",
        "2024-01-01T10:01:00Z",
        event_type="registry_modification",
        target=NON_AUTOSTART_KEY,  # inside the window, but not an autostart key
    )

    assert (
        detect_registry_persistence([proc, reg], build_graph([proc, reg]), []) is None
    )


def test_reg_persist_requires_same_host() -> None:
    proc = _event(
        "p", "2024-01-01T10:00:00Z", event_type="process_execution", source="HOST01"
    )
    reg = _event(
        "r",
        "2024-01-01T10:01:00Z",
        event_type="registry_modification",
        source="HOST02",
        target=AUTOSTART_KEY,
    )

    assert (
        detect_registry_persistence([proc, reg], build_graph([proc, reg]), []) is None
    )


def test_psh_staging_fires_on_attack_neighborhood() -> None:
    attack = _attack_events()
    psh = next(
        e
        for e in attack
        if e.target == "powershell.exe"
        and "DisableRealtimeMonitoring" in e.metadata.get("scriptblock", "")
    )
    download = next(e for e in attack if e.target == r"C:\temp\stage2.ps1")

    conclusion = detect_powershell_staging([psh, download], build_graph(attack), [])

    assert conclusion is not None
    assert conclusion.rule_id == "PSH-STAGING-01"
    assert conclusion.technique_id == "T1059.001"
    assert conclusion.tactic == "Execution"
    assert conclusion.evidence[0].event_ids == [psh.event_id, download.event_id]


def test_psh_staging_requires_execution_before_download() -> None:
    download = _event("d", "2024-01-01T10:00:30Z", event_type="file_download")
    psh = _event("p", "2024-01-01T10:01:00Z", event_type="powershell_execution")

    assert (
        detect_powershell_staging([psh, download], build_graph([psh, download]), [])
        is None
    )


def test_psh_staging_returns_none_outside_time_window() -> None:
    psh = _event("p", "2024-01-01T10:00:00Z", event_type="powershell_execution")
    download = _event("d", "2024-01-01T10:40:00Z", event_type="file_download")

    assert (
        detect_powershell_staging([psh, download], build_graph([psh, download]), [])
        is None
    )


def test_persistence_established_fires_when_staging_fact_present() -> None:
    attack = _attack_events()
    staging = _staging_conclusion(attack)
    reg = next(
        e
        for e in attack
        if e.target == r"HKLM:\Software\Microsoft\Windows\CurrentVersion\Run\Updater"
    )

    conclusion = detect_persistence_established(attack, build_graph(attack), [staging])

    assert conclusion is not None
    assert conclusion.rule_id == "PERSIST-ESTABLISHED-01"
    assert conclusion.technique_id == "T1547.001"
    assert conclusion.tactic == "Persistence"
    assert conclusion.evidence[0].parent_conclusion_id == staging.conclusion_id
    assert set(conclusion.evidence[0].event_ids) == set(
        staging.evidence[0].event_ids
    ) | {reg.event_id}


def test_persistence_established_requires_staging_fact() -> None:
    attack = _attack_events()
    # Attack data has reg mods, but no staging fact -> must not fire.
    assert detect_persistence_established(attack, build_graph(attack), []) is None


def test_persistence_established_respects_time_window() -> None:
    psh = _event("p", "2024-01-01T10:00:00Z", event_type="powershell_execution")
    download = _event("d", "2024-01-01T10:00:30Z", event_type="file_download")
    staging = _staging_conclusion([psh, download])
    reg = _event(
        "r",
        "2024-01-01T10:10:00Z",
        event_type="registry_modification",  # ~9.5 min later
    )

    neighborhood = [psh, download, reg]
    conclusion = detect_persistence_established(
        neighborhood, build_graph(neighborhood), [staging]
    )

    assert conclusion is None


def test_persistence_established_requires_same_host() -> None:
    psh = _event(
        "p", "2024-01-01T10:00:00Z", event_type="powershell_execution", source="HOST01"
    )
    download = _event(
        "d", "2024-01-01T10:00:30Z", event_type="file_download", source="HOST01"
    )
    staging = _staging_conclusion([psh, download])
    reg = _event(
        "r", "2024-01-01T10:01:00Z", event_type="registry_modification", source="HOST02"
    )

    neighborhood = [psh, download, reg]
    conclusion = detect_persistence_established(
        neighborhood, build_graph(neighborhood), [staging]
    )

    assert conclusion is None


def test_all_rules_fire_on_full_attack_neighborhood() -> None:
    attack = _attack_events()
    graph = build_graph(attack)

    assert detect_registry_persistence(attack, graph, []) is not None
    staging = detect_powershell_staging(attack, graph, [])
    assert staging is not None
    assert detect_persistence_established(attack, graph, [staging]) is not None


def test_all_rules_return_none_on_benign_neighborhood() -> None:
    benign = _benign_events()
    graph = build_graph(benign)

    assert detect_registry_persistence(benign, graph, []) is None
    assert detect_powershell_staging(benign, graph, []) is None
    assert detect_persistence_established(benign, graph, []) is None


# ---------------------------------------------------------------------------
# REG-PERSIST-01 — writer identity (Phase 3 Step 2)
# ---------------------------------------------------------------------------

WRITER = r"C:\Windows\System32\evil.exe"


def test_reg_persist_writer_image_match_fires() -> None:
    proc = _event(
        "p",
        "2024-01-01T10:00:00Z",
        event_type="process_execution",
        target="launcher.exe",
        metadata={"Image": r"C:\Windows\System32\Evil.exe"},
    )
    reg = _event(
        "r",
        "2024-01-01T10:01:00Z",
        event_type="registry_modification",
        target=AUTOSTART_KEY,
        metadata={"Image": WRITER},
    )

    conclusion = detect_registry_persistence([proc, reg], build_graph([proc, reg]), [])

    assert conclusion is not None
    assert conclusion.rule_id == "REG-PERSIST-01"
    assert conclusion.confidence == 0.6
    assert conclusion.evidence[0].event_ids == [proc.event_id, reg.event_id]


def test_reg_persist_writer_image_without_matching_process_does_not_fire() -> None:
    proc = _event(
        "p",
        "2024-01-01T10:00:00Z",
        event_type="process_execution",
        target="good.exe",
        metadata={"Image": r"C:\Windows\System32\good.exe"},
    )
    reg = _event(
        "r",
        "2024-01-01T10:01:00Z",
        event_type="registry_modification",
        target=AUTOSTART_KEY,
        metadata={"Image": WRITER},
    )

    assert (
        detect_registry_persistence([proc, reg], build_graph([proc, reg]), []) is None
    )


def test_reg_persist_without_writer_image_falls_back() -> None:
    # The synthetic CSV records no Image, so the old any-prior-process
    # fallback must still fire -- at the lower confidence.
    proc = _event("p", "2024-01-01T10:00:00Z", event_type="process_execution")
    reg = _event(
        "r",
        "2024-01-01T10:01:00Z",
        event_type="registry_modification",
        target=AUTOSTART_KEY,
    )

    conclusion = detect_registry_persistence([proc, reg], build_graph([proc, reg]), [])

    assert conclusion is not None
    assert conclusion.confidence == 0.4
    assert conclusion.evidence[0].event_ids == [proc.event_id, reg.event_id]


def test_reg_persist_non_autostart_key_with_writer_still_does_not_fire() -> None:
    proc = _event(
        "p",
        "2024-01-01T10:00:00Z",
        event_type="process_execution",
        metadata={"Image": WRITER},
    )
    reg = _event(
        "r",
        "2024-01-01T10:01:00Z",
        event_type="registry_modification",
        target=NON_AUTOSTART_KEY,
        metadata={"Image": WRITER},
    )

    assert (
        detect_registry_persistence([proc, reg], build_graph([proc, reg]), []) is None
    )


# ---------------------------------------------------------------------------
# C2-BEACON-01 — public destination requirement (Phase 3 Step 2)
# ---------------------------------------------------------------------------


def _beacon_events(ip: str, port: int, *, metadata_extra: dict | None = None):
    proc = _event(
        "p", "2024-01-01T10:00:00Z", event_type="process_execution", target="evil.exe"
    )
    metadata = {"DestinationPort": port}
    metadata.update(metadata_extra or {})
    net = _event(
        "n",
        "2024-01-01T10:01:00Z",
        event_type="network_connection",
        target=ip,
        metadata=metadata,
    )
    return proc, net


def test_network_beacon_fires_on_public_destination_nonstandard_port() -> None:
    proc, net = _beacon_events("185.220.101.1", 4444)

    conclusion = detect_network_beacon([proc, net], build_graph([proc, net]), [])

    assert conclusion is not None
    assert conclusion.rule_id == "C2-BEACON-01"
    assert conclusion.confidence == 0.3


def test_network_beacon_does_not_fire_on_private_destination() -> None:
    # RFC1918 destination on a non-standard port: cannot confirm public -> no fire.
    proc, net = _beacon_events("10.0.0.5", 4444)

    assert detect_network_beacon([proc, net], build_graph([proc, net]), []) is None


def test_network_beacon_does_not_fire_on_multicast_destination() -> None:
    # 239.255.255.250 is SSDP multicast; on this Python ``is_global`` alone
    # still returns True, so the rule must exclude multicast explicitly.
    proc, net = _beacon_events("239.255.255.250", 1900)

    assert detect_network_beacon([proc, net], build_graph([proc, net]), []) is None


def test_network_beacon_does_not_fire_on_benign_port() -> None:
    proc, net = _beacon_events("185.220.101.1", 443)

    assert detect_network_beacon([proc, net], build_graph([proc, net]), []) is None


def test_network_beacon_uses_normalized_ip_when_destination_ip_absent() -> None:
    # No DestinationIp field: fall back to the parser's _ip_norm.
    proc = _event(
        "p", "2024-01-01T10:00:00Z", event_type="process_execution", target="evil.exe"
    )
    net = _event(
        "n",
        "2024-01-01T10:01:00Z",
        event_type="network_connection",
        target="not-an-ip",
        metadata={"_ip_norm": "185.220.101.1", "DestinationPort": 4444},
    )

    conclusion = detect_network_beacon([proc, net], build_graph([proc, net]), [])

    assert conclusion is not None
