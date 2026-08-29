"""
Smoke tests for cephtrace_report.py.

These run against the small committed sample logs in tools/sample-logs/ so
they are offline and fast.  The module is imported directly (tox sets
PYTHONPATH=tools); cephtrace_report has a hyphen-free name precisely so it is
importable here.
"""
import json
import os
import re
import runpy
import sys

import pytest

import cephtrace_report  # pylint: disable=E0401

SAMPLES = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "tools", "sample-logs",
)
OSD_LOG = os.path.join(SAMPLES, "osdtrace_data.log")
RADOS_LOG = os.path.join(SAMPLES, "radostrace_data.log")
RADOS_CSV = os.path.join(SAMPLES, "radostrace_data.csv")


def _run(path, capsys):
    """Run the tool's main() against a file path and return stdout."""
    argv = sys.argv
    sys.argv = ["cephtrace_report.py", path]
    try:
        rc = cephtrace_report.main()
    finally:
        sys.argv = argv
    return rc, capsys.readouterr().out


def test_osdtrace_report(capsys):
    """osdtrace sample renders every headline section and the op types."""
    rc, out = _run(OSD_LOG, capsys)
    assert rc == 0
    assert "osdtrace summary - 11 OSD ops" in out
    for token in ("op_r", "op_w", "subop_w"):
        assert token in out
    assert "where the time goes" in out
    assert "op latency distribution" in out
    # bluestore dominates this write-heavy sample; kv_commit must surface
    assert "kv_commit" in out
    # two distinct OSDs in the sample -> per-OSD section is drawn
    assert "per-OSD p95 latency" in out
    assert "slowest ops" in out
    assert "analyze_osdtrace_output.py" in out


def test_radostrace_space_report(capsys):
    """Space-formatted radostrace sample renders the client-side sections."""
    rc, out = _run(RADOS_LOG, capsys)
    assert rc == 0
    assert "radostrace summary" in out
    assert "reads" in out and "writes" in out
    assert "latency distribution" in out
    assert "slowest ops" in out
    assert "analyze_radostrace_output.py" in out


def test_radostrace_csv_report(capsys):
    """CSV-formatted (radostrace -o) sample is detected and rendered."""
    rc, out = _run(RADOS_CSV, capsys)
    assert rc == 0
    assert "radostrace summary" in out
    assert "latency distribution" in out


def _embedded_json(html):
    """Pull the embedded payload back out of a generated report."""
    match = re.search(r"const DATA = (\{.*?\});", html, re.S)
    return json.loads(match.group(1))


def test_html_osdtrace(tmp_path, capsys):
    """--html on osdtrace writes a self-contained report with valid payload."""
    out = tmp_path / "osd.html"
    argv = sys.argv
    sys.argv = ["cephtrace_report.py", "--html", str(out), OSD_LOG]
    try:
        rc = cephtrace_report.main()
    finally:
        sys.argv = argv
    assert rc == 0
    assert f"wrote {out}" in capsys.readouterr().out
    html = out.read_text(encoding="utf-8")
    # self-contained: placeholder substituted, no external script/style refs
    assert "__CEPHTRACE_DATA__" not in html
    assert "<script src" not in html and "http" not in html.split("foot")[0]
    payload = _embedded_json(html)
    assert payload["kind"] == "osdtrace"
    assert payload["summary"]["ops"] == 11
    # two OSDs in the sample -> per-group histograms for cross-filtering
    assert payload["groupLabel"] == "OSD"
    assert sorted(payload["histGroups"]) == ["0", "2"]
    assert len(payload["histOverall"]) == len(payload["histLabels"])
    assert payload["stages"] and payload["kvCommit"] > 0
    assert payload["timeline"] and payload["slowest"]


def test_html_radostrace(tmp_path):
    """--html on radostrace (CSV input) writes a valid pool-keyed report."""
    out = tmp_path / "rados.html"
    argv = sys.argv
    sys.argv = ["cephtrace_report.py", "--html", str(out), RADOS_CSV]
    try:
        rc = cephtrace_report.main()
    finally:
        sys.argv = argv
    assert rc == 0
    payload = _embedded_json(out.read_text(encoding="utf-8"))
    assert payload["kind"] == "radostrace"
    assert payload["groupLabel"] == "Pool"
    assert "reads" in payload["summary"] and "writes" in payload["summary"]
    assert payload["slowest"][0]["lat"] >= payload["slowest"][-1]["lat"]


def test_html_requires_filename(capsys):
    """--html with no following filename fails with rc=2."""
    argv = sys.argv
    sys.argv = ["cephtrace_report.py", "--html"]
    try:
        rc = cephtrace_report.main()
    finally:
        sys.argv = argv
    assert rc == 2
    assert "requires an output filename" in capsys.readouterr().err


def test_no_rows_returns_error(tmp_path, capsys):
    """A file with no recognizable trace rows fails cleanly (rc=1)."""
    junk = tmp_path / "junk.log"
    junk.write_text("hello\nworld\n", encoding="utf-8")
    rc, _ = _run(str(junk), capsys)
    assert rc == 1


def test_help_runs(capsys):
    """--help prints the module docstring and exits 0."""
    argv = sys.argv
    sys.argv = ["cephtrace_report.py", "--help"]
    try:
        rc = cephtrace_report.main()
    finally:
        sys.argv = argv
    assert rc == 0
    assert "one-screen visual summary" in capsys.readouterr().out


def test_runs_as_script():
    """The committed osdtrace sample runs end-to-end as a script (no import
    side-effects, exit code 0)."""
    argv = sys.argv
    sys.argv = ["cephtrace_report.py", OSD_LOG]
    try:
        with pytest.raises(SystemExit) as exc:
            runpy.run_path(
                os.path.join(SAMPLES, "..", "cephtrace_report.py"),
                run_name="__main__",
            )
        assert exc.value.code == 0
    finally:
        sys.argv = argv
