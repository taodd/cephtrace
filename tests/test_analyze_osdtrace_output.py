#!/usr/bin/env python3
"""
Unit tests for analyze_osdtrace_output.py
"""

import subprocess
from pathlib import Path
import pytest

GOLDEN_OUTPUT = """osd.22:
  op_r lat (μsec): min=134648, max=569724, avg=354957.65, stdev=137523.30, samples=34
  lat percentiles (μsec):
  |   1.00th=[134648.00],  5.00th=[149080.00], 10.00th=[175910.00],
  |  20.00th=[247777.00], 30.00th=[256487.00], 40.00th=[269418.00],
  |  50.00th=[308639.00], 60.00th=[417207.00], 70.00th=[479059.00],
  |  80.00th=[487521.00], 90.00th=[540136.00], 95.00th=[565483.00],
  |  99.00th=[569724.00], 99.50th=[569724.00], 99.90th=[569724.00]

  op_w lat (μsec): min=102307, max=973432, avg=341169.62, stdev=196630.90, samples=235
  lat percentiles (μsec):
  |   1.00th=[107408.00],  5.00th=[117445.00], 10.00th=[144097.00],
  |  20.00th=[152075.00], 30.00th=[203883.00], 40.00th=[212189.00],
  |  50.00th=[243685.00], 60.00th=[359714.00], 70.00th=[477859.00],
  |  80.00th=[541498.00], 90.00th=[596082.00], 95.00th=[654882.00],
  |  99.00th=[918978.00], 99.50th=[930958.00], 99.90th=[973432.00]

  subop_w lat (μsec): min=116422, max=587255, avg=340587.18, stdev=126069.23, samples=171
  lat percentiles (μsec):
  |   1.00th=[119872.00],  5.00th=[164979.00], 10.00th=[168396.00],
  |  20.00th=[212618.00], 30.00th=[272828.00], 40.00th=[286951.00],
  |  50.00th=[335251.00], 60.00th=[366706.00], 70.00th=[415880.00],
  |  80.00th=[462069.00], 90.00th=[530951.00], 95.00th=[563831.00],
  |  99.00th=[584956.00], 99.50th=[587255.00], 99.90th=[587255.00]

"""

GOLDEN_OUTPUT_IN_MS = """osd.22:
  op_r lat (msec): min=134.648, max=569.724, avg=354.96, stdev=137.52, samples=34
  lat percentiles (msec):
  |   1.00th=[134.65],  5.00th=[149.08], 10.00th=[175.91],
  |  20.00th=[247.78], 30.00th=[256.49], 40.00th=[269.42],
  |  50.00th=[308.64], 60.00th=[417.21], 70.00th=[479.06],
  |  80.00th=[487.52], 90.00th=[540.14], 95.00th=[565.48],
  |  99.00th=[569.72], 99.50th=[569.72], 99.90th=[569.72]

  op_w lat (msec): min=102.307, max=973.432, avg=341.17, stdev=196.63, samples=235
  lat percentiles (msec):
  |   1.00th=[107.41],  5.00th=[117.44], 10.00th=[144.10],
  |  20.00th=[152.07], 30.00th=[203.88], 40.00th=[212.19],
  |  50.00th=[243.69], 60.00th=[359.71], 70.00th=[477.86],
  |  80.00th=[541.50], 90.00th=[596.08], 95.00th=[654.88],
  |  99.00th=[918.98], 99.50th=[930.96], 99.90th=[973.43]

  subop_w lat (msec): min=116.422, max=587.255, avg=340.59, stdev=126.07, samples=171
  lat percentiles (msec):
  |   1.00th=[119.87],  5.00th=[164.98], 10.00th=[168.40],
  |  20.00th=[212.62], 30.00th=[272.83], 40.00th=[286.95],
  |  50.00th=[335.25], 60.00th=[366.71], 70.00th=[415.88],
  |  80.00th=[462.07], 90.00th=[530.95], 95.00th=[563.83],
  |  99.00th=[584.96], 99.50th=[587.25], 99.90th=[587.25]

"""

GOLDEN_KV_COMMIT_OUTPUT = """osd.22:
  op_w kv_commit (μsec): min=0, max=574911, avg=7768.29, stdev=52885.97, samples=235
  kv_commit percentiles (μsec):
  |   1.00th=[     0.00],  5.00th=[     0.00], 10.00th=[     0.00],
  |  20.00th=[   236.00], 30.00th=[   334.00], 40.00th=[   409.00],
  |  50.00th=[   476.00], 60.00th=[   618.00], 70.00th=[   852.00],
  |  80.00th=[  8859.00], 90.00th=[ 13936.00], 95.00th=[ 14203.00],
  |  99.00th=[ 18253.00], 99.50th=[574852.00], 99.90th=[574911.00]

  subop_w kv_commit (μsec): min=0, max=580104, avg=16646.40, stdev=61704.87, samples=171
  kv_commit percentiles (μsec):
  |   1.00th=[     0.00],  5.00th=[     0.00], 10.00th=[     0.00],
  |  20.00th=[     0.00], 30.00th=[  8917.00], 40.00th=[  9115.00],
  |  50.00th=[  9325.00], 60.00th=[ 13944.00], 70.00th=[ 18065.00],
  |  80.00th=[ 18139.00], 90.00th=[ 18227.00], 95.00th=[ 18256.00],
  |  99.00th=[576830.00], 99.50th=[580104.00], 99.90th=[580104.00]

"""


GOLDEN_RECV_LAT_OUTPUT = """osd.22:
  op_r recv_lat (μsec): min=2, max=16, avg=6.53, stdev=3.91, samples=34
  recv_lat percentiles (μsec):
  |   1.00th=[ 2.00],  5.00th=[ 2.00], 10.00th=[ 3.00],
  |  20.00th=[ 3.00], 30.00th=[ 4.00], 40.00th=[ 5.00],
  |  50.00th=[ 6.00], 60.00th=[ 6.00], 70.00th=[ 7.00],
  |  80.00th=[11.00], 90.00th=[13.00], 95.00th=[14.00],
  |  99.00th=[16.00], 99.50th=[16.00], 99.90th=[16.00]

  op_w recv_lat (μsec): min=1, max=1696, avg=41.98, stdev=162.80, samples=235
  recv_lat percentiles (μsec):
  |   1.00th=[   2.00],  5.00th=[   3.00], 10.00th=[   5.00],
  |  20.00th=[   7.00], 30.00th=[   8.00], 40.00th=[  10.00],
  |  50.00th=[  12.00], 60.00th=[  15.00], 70.00th=[  19.00],
  |  80.00th=[  25.00], 90.00th=[  44.00], 95.00th=[  78.00],
  |  99.00th=[ 941.00], 99.50th=[1311.00], 99.90th=[1696.00]

  subop_w recv_lat (μsec): min=4, max=2376, avg=64.89, stdev=275.50, samples=171
  recv_lat percentiles (μsec):
  |   1.00th=[   4.00],  5.00th=[   7.00], 10.00th=[   8.00],
  |  20.00th=[  10.00], 30.00th=[  12.00], 40.00th=[  13.00],
  |  50.00th=[  16.00], 60.00th=[  20.00], 70.00th=[  25.00],
  |  80.00th=[  29.00], 90.00th=[  47.00], 95.00th=[  92.00],
  |  99.00th=[2345.00], 99.50th=[2376.00], 99.90th=[2376.00]

"""

GOLDEN_INFER_OUTPUT = f"""osd.22:
  op_w:
    38.66% from queue_lat
    23.01% from bluestore_lat
     8.82% from osd_lat
     0.02% from recv_lat
     0.00% from dispatch_lat
     0.00% from throttle_lat
  op_r:
    96.60% from queue_lat
     0.11% from bluestore_lat
     0.01% from osd_lat
     0.00% from dispatch_lat
     0.00% from recv_lat
     0.00% from throttle_lat
  subop_w:
    90.42% from queue_lat
    34.09% from bluestore_lat
     0.02% from recv_lat
     0.01% from osd_lat
     0.00% from dispatch_lat
     0.00% from throttle_lat

"""

GOLDEN_SORTED_OUTPUT_LAST_3_LINES = """
osd 22 pg 24.5af op op_w size 4096 client 175806839 tid 205553815 throttle_lat 1 recv_lat 14 dispatch_lat 9 queue_lat 61 osd_lat 136 peers [(21, 918780), (47, 798)] bluestore_lat 567 (prepare 80 aio_wait 129 aio_size 1 seq_wait 6 kv_commit 351) lat_type op_lat lat 918978
osd 22 pg 24.5af op op_w size 4096 client 175806839 tid 205553863 throttle_lat 1 recv_lat 8 dispatch_lat 6 queue_lat 22 osd_lat 113 peers [(21, 930832), (47, 1189)] bluestore_lat 415 (prepare 53 aio_wait 76 aio_size 1 seq_wait 6 kv_commit 278) lat_type op_lat lat 930958
osd 22 pg 24.167 op op_w size 4096 client 220655812 tid 125622930 throttle_lat 1 recv_lat 7 dispatch_lat 5 queue_lat 39 osd_lat 231 peers [(8, 1109), (21, 973160)] bluestore_lat 614 (prepare 69 aio_wait 112 aio_size 1 seq_wait 4 kv_commit 426) lat_type op_lat lat 973432
"""

@pytest.mark.parametrize("flags,expected_output", [
    ("", GOLDEN_OUTPUT),
    ("-m", GOLDEN_OUTPUT_IN_MS),
    ("-o 22", GOLDEN_OUTPUT),
    ("-o 23333", ""),
    ("-f kv_commit", GOLDEN_KV_COMMIT_OUTPUT),
    ("-f recv_lat", GOLDEN_RECV_LAT_OUTPUT),
    ("-i", GOLDEN_INFER_OUTPUT),
], ids=["no_flags", "in_ms", "single_osd", "nonexistent_osd", "kv_commit", "recv_lat", "infer"])
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


def test_e2e_sort_sample_log():
    """Test that analyzing the sample log with -s sorts the OSDs by avg latency"""
    project_root = Path(__file__).parent.parent
    script_path = project_root / "tools" / "analyze_osdtrace_output.py"
    sample_log = project_root / "tools" / "sample-logs" / "osdtrace_data.log"

    cmd = ["python3", str(script_path), str(sample_log), "-s"]
    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        check=False
    )

    actual_lines = result.stdout.strip().split('\n')
    actual_last_3_lines = "\n" + "\n".join(actual_lines[-3:]) + "\n"

    assert actual_last_3_lines == GOLDEN_SORTED_OUTPUT_LAST_3_LINES
    assert result.returncode == 0