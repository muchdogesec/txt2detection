import uuid
from unittest.mock import MagicMock, patch


from txt2detection.__main__ import (
    run_txt2detection,
)
from txt2detection.models import SigmaRuleDetection


def test_run_txt2detection_ai_branch(monkeypatch):
    input_text = "my text"
    ai_provider = MagicMock()
    name = "name"
    identity = None
    tlp_level = "red"
    monkeypatch.setenv('INPUT_TOKEN_LIMIT', "100")
    report_id = uuid.uuid4()

    with patch('txt2detection.__main__.validate_token_count') as mock_validate_token_count, patch('txt2detection.bundler.Bundler.bundle_detections') as mock_bundle_detection:
        bundler = run_txt2detection(name, identity, tlp_level, input_text, [], report_id, ai_provider)
        mock_validate_token_count.assert_called_once_with(100, input_text, ai_provider)
        ai_provider.get_detections.assert_called_once_with(input_text)
        mock_bundle_detection.assert_called_once_with(ai_provider.get_detections.return_value)
        assert bundler.report.description == input_text
        assert bundler.report.name == name
        assert bundler.report.id == "report--"+str(report_id)

@patch("txt2detection.__main__.get_sigma_detections")
def test_run_txt2detection_sigma_branch(mock_get_sigma_detections, monkeypatch):
    detection = SigmaRuleDetection(
        title="Test Detection",
        description="Detects something suspicious.",
        detection=dict(condition='selection1'),
        tags=["tlp.red"],
        id=str(uuid.uuid4()),
        external_references=[],
        logsource=dict(
            category="network-connection",
            product="firewall",
        ),
    )

    mock_get_sigma_detections.return_value = detection
    input_text = "my text"
    ai_provider = MagicMock()
    name = "name"
    identity = None
    tlp_level = "red"
    report_id = uuid.uuid4()
    monkeypatch.setenv('INPUT_TOKEN_LIMIT', "100")
    with patch('txt2detection.__main__.validate_token_count') as mock_validate_token_count, patch('txt2detection.bundler.Bundler.bundle_detections') as mock_bundle_detection:
        bundler = run_txt2detection(name, identity, tlp_level, "", [], report_id, ai_provider, sigma_file="sigma_yaml")
        mock_get_sigma_detections.assert_called_once()
        assert bundler is not None
        assert bundler.report.id == "report--"+str(report_id)
        assert bundler.report.description == detection.description
        assert str(detection.detection_id) == str(report_id)
        assert detection.references == bundler.reference_urls
        # assert detection.author == bundler.report.created_by_ref

