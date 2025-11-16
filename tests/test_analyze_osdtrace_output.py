#!/usr/bin/env python3
"""
Unit tests for analyze_osdtrace_output.py
"""

import subprocess
from pathlib import Path
import pytest
from . import analyze_osdtrace_golden_outputs as golden


@pytest.mark.parametrize(
    "flags,expected_output",
    [
        ("", golden.GOLDEN_OUTPUT),
        ("-o 6 -m", golden.GOLDEN_OUTPUT_OSD_6_IN_MS),
        ("-o 6", golden.GOLDEN_OUTPUT_OSD_6),
        ("-o 23333", ""),
        ("-f kv_commit", golden.GOLDEN_KV_COMMIT_OUTPUT),
        ("-f recv_lat", golden.GOLDEN_RECV_LAT_OUTPUT),
        ("-i", golden.GOLDEN_INFER_OUTPUT),
    ],
    ids=[
        "no_flags",
        "in_ms",
        "single_osd",
        "nonexistent_osd",
        "kv_commit",
        "recv_lat",
        "infer"
    ],
)
def test_e2e_analyze_sample_log(flags, expected_output):
    """Test that analyzing the sample log produces expected output"""
    project_root = Path(__file__).parent.parent
    script_path = project_root / "tools" / "analyze_osdtrace_output.py"
    sample_log = project_root / "tools" / "sample-logs" / "osdtrace_data.log"

    cmd = ["python3", str(script_path), str(sample_log)]
    if flags:
        cmd.extend(flags.split())

    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        check=False
    )

    assert result.stdout == expected_output
    assert result.returncode == 0


@pytest.mark.parametrize(
    "flags,expected_output",
    [
        ("", golden.GOLDEN_SORTED_OUTPUT_LAST_3_LINES),
        ("-f recv_lat", golden.GOLDEN_SORTED_OUTPUT_LAST_3_LINES_RECV_LAT),
    ],
    ids=[
        "plain",
        "recv_lat",
    ],
)
def test_e2e_sort_sample_log(flags, expected_output):
    """Test that sorting the sample log is as expected."""
    project_root = Path(__file__).parent.parent
    script_path = project_root / "tools" / "analyze_osdtrace_output.py"
    sample_log = project_root / "tools" / "sample-logs" / "osdtrace_data.log"

    cmd = ["python3", str(script_path), str(sample_log), "-s"]
    if flags:
        cmd.extend(flags.split())

    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        check=False
    )

    actual_lines = result.stdout.strip().split('\n')
    actual_last_3_lines = "\n" + "\n".join(actual_lines[-3:]) + "\n"

    assert actual_last_3_lines == expected_output
    assert result.returncode == 0
