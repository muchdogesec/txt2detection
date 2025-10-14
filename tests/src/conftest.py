import pytest

from txt2detection.bundler import Bundler
from datetime import datetime



@pytest.fixture
def bundler_instance():
    return Bundler(
        name="Test Report",
        identity=None,
        tlp_level="red",
        description="This is a test report.",
        labels=["tlp.red", "test.test-var"],
        created=datetime(2025, 1, 1),
        report_id="74e36652-00f5-4dca-bf10-9f02fc996dcc",
    )