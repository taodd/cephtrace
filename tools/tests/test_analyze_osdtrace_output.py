#!/usr/bin/env python3
"""
End to end tests for analyze_osdtrace_output.py
"""

import sys
from io import StringIO
from pathlib import Path
import pytest

from . import analyze_osdtrace_golden_outputs as golden
from .. import analyze_osdtrace_output

SAMPLE_LOG = Path(__file__).parent.parent / "sample-logs" / "osdtrace_data.log"


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
        "infer",
    ],
)
def test_e2e_analyze_sample_log(flags, expected_output):
    """Test that analyzing the sample log produces expected output"""
    parser = analyze_osdtrace_output.create_arg_parser()
    script_args = [str(SAMPLE_LOG)] + (flags.split() if flags else [])
    args = parser.parse_args(script_args)

    old_stdout = sys.stdout
    sys.stdout = captured_output = StringIO()

    try:
        analyze_osdtrace_output.run(args)
    finally:
        sys.stdout = old_stdout

    assert captured_output.getvalue() == expected_output


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
    parser = analyze_osdtrace_output.create_arg_parser()
    script_args = [str(SAMPLE_LOG), "-s"] + (flags.split() if flags else [])
    args = parser.parse_args(script_args)

    old_stdout = sys.stdout
    sys.stdout = captured_output = StringIO()

    try:
        analyze_osdtrace_output.run(args)
    finally:
        sys.stdout = old_stdout

    actual_lines = captured_output.getvalue().strip().split('\n')
    actual_last_3_lines = "\n" + "\n".join(actual_lines[-3:]) + "\n"

    assert actual_last_3_lines == expected_output
