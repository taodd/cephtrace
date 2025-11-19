"""
Pytest configuration and shared fixtures for test data.
"""
import io
import tarfile
from pathlib import Path
import requests
import pytest

# flake8: noqa: E501
URL = "https://github.com/taodd/cephtrace/releases/download/fixtures/sample_osdtrace_data.tar.gz"


@pytest.fixture(scope="session")
def sample_osdtrace_log(tmp_path_factory) -> Path:
    """Download and extract sample fixture data for tests."""
    fixture_dir = tmp_path_factory.mktemp("fixtures")

    try:
        response = requests.get(URL, timeout=30)
        response.raise_for_status()

        with tarfile.open(fileobj=io.BytesIO(response.content), mode='r:gz') as tar:
            tar.extractall(path=fixture_dir, filter='data')

    except requests.RequestException as e:
        pytest.fail(f"Failed to download fixture data: {e}")
    except tarfile.TarError as e:
        pytest.fail(f"Failed to extract tarball: {e}")

    log_file = fixture_dir / "osdtrace_data.log"

    if not log_file.exists():
        pytest.fail(f"Could not find expected sample osdtrace_data log file {log_file}")

    return log_file
