"""
End to end tests for analyze_osdtrace_output.py
"""

import pytest

import analyze_osdtrace_golden_outputs as golden
import analyze_osdtrace_output  # pylint: disable=E0401


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
def test_e2e_analyze_sample_log(
    sample_osdtrace_log,
    flags,
    expected_output,
    capsys,
):
    """Test that analyzing the sample log produces expected output

    sample_osdtrace_log: Path to the sample osdtrace log file
    (this comes from fixtures set in conftest.py)
    """
    parser = analyze_osdtrace_output.create_arg_parser()
    script_args = [str(sample_osdtrace_log)] + flags.split()
    analyze_osdtrace_output.run(parser.parse_args(script_args))

    assert capsys.readouterr().out == expected_output


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
def test_e2e_sort_sample_log(
    sample_osdtrace_log,
    flags,
    expected_output,
    capsys,
):
    """Test that sorting the sample log is as expected.

    sample_osdtrace_log: Path to the sample osdtrace log file
    (this comes from fixtures set in conftest.py)
    """
    parser = analyze_osdtrace_output.create_arg_parser()
    script_args = [str(sample_osdtrace_log), "-s"] + flags.split()
    analyze_osdtrace_output.run(parser.parse_args(script_args))

    stdout = capsys.readouterr().out
    tail_out = stdout.strip().split("\n")[-3:]

    assert "\n" + "\n".join(tail_out) + "\n" == expected_output
