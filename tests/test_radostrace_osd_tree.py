"""Regression tests for host mapping in radostrace analysis."""

import pytest

import analyze_radostrace_output  # pylint: disable=E0401


@pytest.mark.parametrize("indent", ["", " ", "  ", "\t"])
def test_padded_host_ids(tmp_path, indent):
    """Preserve host membership when negative IDs have leading padding."""
    tree = tmp_path / "osd-tree.txt"
    tree.write_text(
        "ID CLASS WEIGHT TYPE NAME STATUS REWEIGHT PRI-AFF\n"
        "-1 2.0 root default\n"
        "-3 1.0 host host-a\n"
        " 0 hdd 1.0 osd.0 up 1.0 1.0\n"
        f"{indent}-12 1.0 host host-b\n"
        " 1 hdd 1.0 osd.1 up 1.0 1.0\n",
        encoding="utf-8",
    )
    assert analyze_radostrace_output.parse_osd_tree(str(tree)) == {
        "0": "host-a", "1": "host-b",
    }
