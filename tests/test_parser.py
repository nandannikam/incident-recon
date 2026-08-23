import pandas as pd
from src.parser import parse_log
import os

def test_parse_log(tmp_path):
    csv_content = """timestamp,source,event_type,actor,target,metadata
2024-01-01T10:00:00Z,HOST01,process_execution,USER01,cmd.exe,"{'pid':123}"
2024-01-01T10:01:00Z,HOST01,file_creation,USER01,file.txt,"{}"
BAD_ROW_NO_TIMESTAMP,HOST01,file_creation,USER01,file.txt,"{}"
"""
    test_file = tmp_path / "test_data.csv"
    test_file.write_text(csv_content)

    events = parse_log(str(test_file))

    assert len(events) == 2 
    assert events[0].event_type == "process_execution"
    assert events[1].event_type == "file_creation"
    assert events[0].event_id == f"{test_file}:0"