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
def sample_fixture_data(tmp_path_factory) -> Path:
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
    except Exception as e:
        pytest.fail(f"Unexpected error downloading fixture: {e}")
    
    return fixture_dir


@pytest.fixture(scope="session")
def sample_osdtrace_log(sample_fixture_data: Path) -> Path:
    """Returns path to the downloaded sample osdtrace data log file."""
    for pattern in ["*osdtrace_data*.log"]:
        log_files = list(sample_fixture_data.glob(pattern))
        if log_files:
            return log_files[0]

    pytest.fail(f"Could not find any sample_osdtrace_data log files in {sample_fixture_data}")
