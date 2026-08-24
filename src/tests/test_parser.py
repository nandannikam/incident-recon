import pytest

from app.parser import parse_log


def test_valid_rows_and_bad_row_are_skipped_and_counted(tmp_path):
    csv_path = tmp_path / "mixed.csv"
    csv_path.write_text(
        "timestamp,source,event_type,actor,target,metadata\n"
        '2024-01-01T10:00:00Z,HOST01,process_execution,USER01,a.exe,"{""pid"": 1}"\n'
        '2024-01-01T10:00:10Z,HOST01,process_execution,USER01,b.exe,"{""pid"": 2}"\n'
        ",HOST01,process_execution,USER01,c.exe,{}\n"  # missing timestamp -> malformed
    )

    result = parse_log(str(csv_path))

    assert result.total_rows == 3
    assert len(result.events) == 2
    assert result.skipped == 1
    assert len(result.errors) == 1


def test_event_id_uses_original_row_number_even_when_input_is_unsorted(tmp_path):
    """Issue #17 regression test: the file is deliberately OUT of
    chronological order. event_id must map to the physical source row,
    while the returned events list must still be sorted by time."""
    csv_path = tmp_path / "unsorted.csv"
    csv_path.write_text(
        "timestamp,source,event_type,actor,target,metadata\n"
        '2024-01-01T10:05:00Z,HOST01,process_execution,USER01,late.exe,{}\n'   # row 0, latest time
        '2024-01-01T10:00:00Z,HOST01,process_execution,USER01,early.exe,{}\n'  # row 1, earliest time
        '2024-01-01T10:02:00Z,HOST01,process_execution,USER01,mid.exe,{}\n'    # row 2, middle time
    )

    result = parse_log(str(csv_path))
    assert result.skipped == 0

    # Returned order must be chronological: early, mid, late.
    assert [e.target for e in result.events] == ["early.exe", "mid.exe", "late.exe"]

    # But event_id must still reference the ORIGINAL row index, not the
    # sorted position.
    by_target = {e.target: e.event_id for e in result.events}
    assert by_target["late.exe"] == f"{csv_path}:0"
    assert by_target["early.exe"] == f"{csv_path}:1"
    assert by_target["mid.exe"] == f"{csv_path}:2"


def test_mixed_timezone_formats_are_normalized_and_sorted_correctly(tmp_path):
    """Issue #18 regression test: a Z-suffixed value, an explicit offset,
    and a naive value must not crash and must sort correctly once
    normalized to UTC."""
    csv_path = tmp_path / "tz.csv"
    csv_path.write_text(
        "timestamp,source,event_type,actor,target,metadata\n"
        '2024-01-01T12:00:00Z,HOST01,process_execution,USER01,utc.exe,{}\n'
        '2024-01-01T13:30:00+05:30,HOST01,process_execution,USER01,offset.exe,{}\n'  # == 08:00 UTC
        '2024-01-01T09:00:00,HOST01,process_execution,USER01,naive.exe,{}\n'          # treated as UTC
    )

    result = parse_log(str(csv_path))
    assert result.skipped == 0
    for e in result.events:
        assert e.timestamp.tzinfo is not None

    # Chronological order once normalized to UTC: offset (08:00) < naive (09:00) < utc (12:00)
    assert [e.target for e in result.events] == ["offset.exe", "naive.exe", "utc.exe"]


def test_row_with_missing_actor_is_skipped_not_coerced_to_nan_string(tmp_path):
    """Issue #20 regression test."""
    csv_path = tmp_path / "missing_actor.csv"
    csv_path.write_text(
        "timestamp,source,event_type,actor,target,metadata\n"
        "2024-01-01T10:00:00Z,HOST01,process_execution,,a.exe,{}\n"
    )

    result = parse_log(str(csv_path))
    assert result.skipped == 1
    assert result.events == []


def test_unparseable_metadata_skips_the_row_instead_of_blanking_it(tmp_path):
    """Issue #19 regression test."""
    csv_path = tmp_path / "bad_meta.csv"
    csv_path.write_text(
        "timestamp,source,event_type,actor,target,metadata\n"
        '2024-01-01T10:00:00Z,HOST01,process_execution,USER01,a.exe,{not valid at all\n'
    )

    result = parse_log(str(csv_path))
    assert result.skipped == 1
    assert result.events == []


def test_json_metadata_with_lowercase_null_and_bool_parses(tmp_path):
    """Issue #21 regression test: real-world/Mordor-style JSON booleans and
    null must parse, which ast.literal_eval alone cannot do."""
    csv_path = tmp_path / "json_meta.csv"
    csv_path.write_text(
        "timestamp,source,event_type,actor,target,metadata\n"
        '2024-01-01T10:00:00Z,HOST01,process_execution,USER01,a.exe,'
        '"{""elevated"": true, ""parent_deleted"": false, ""notes"": null}"\n'
    )

    result = parse_log(str(csv_path))
    assert result.skipped == 0
    meta = result.events[0].metadata
    assert meta["elevated"] is True
    assert meta["parent_deleted"] is False
    assert meta["notes"] is None


def test_nonexistent_file_raises_instead_of_returning_empty_result():
    """Issue #15 regression test."""
    with pytest.raises(FileNotFoundError):
        parse_log("/tmp/this_file_definitely_does_not_exist_12345.csv")


def test_empty_file_raises():
    """Issue #15 regression test — an unreadable/empty file is a distinct
    failure mode from 'zero valid rows in a well-formed file'."""
    import pandas as pd
    with pytest.raises(pd.errors.EmptyDataError):
        parse_log("/dev/null")
