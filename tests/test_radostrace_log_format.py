"""Regression tests for radostrace log format detection."""

import pytest

import analyze_radostrace_output  # pylint: disable=E0401


SPACE_ROW = "123 456 789 1 ab [1,5,8] W 4096 1500\n"
CSV_ROW = '123,456,789,1,ab,"[1,5,8]",W,4096,1500\n'


@pytest.mark.parametrize(
    "preamble,row",
    [
        ("", SPACE_ROW),
        ("", CSV_ROW),
        ("pid client tid pool pg acting WR size latency\n", SPACE_ROW),
        ("pid,client,tid,pool,pg,acting,WR,size,latency\n", CSV_ROW),
        ("\n", SPACE_ROW),
        ("\n", CSV_ROW),
        ("Execution timeout set to 30 seconds.\nVersion check passed\n",
         SPACE_ROW),
    ],
)
def test_parse_log_formats(tmp_path, preamble, row):
    """Count the same operation in CSV and whitespace logs."""
    log = tmp_path / "trace.log"
    log.write_text(preamble + row, encoding="utf-8")
    counts, entries = analyze_radostrace_output.parse_log_file(str(log), 1000)
    assert dict(counts) == {"1": 1, "5": 1, "8": 1}
    assert entries == [["1", "5", "8"]]
