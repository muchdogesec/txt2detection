import json
import os
from pathlib import Path
import sys
from unittest.mock import MagicMock, patch
from pydantic import ValidationError
import pytest
import argparse
from datetime import datetime, timezone

from txt2detection.__main__ import (
    parse_created,
    parse_ref,
    parse_label,
    parse_args,
    main,
)


@pytest.mark.parametrize(
    "input_str, expected_date",
    [
        ("2023-05-01T12:30:45", datetime(2023, 5, 1, 12, 30, 45, tzinfo=timezone.utc)),
        (
            "2024-12-31T23:59:59",
            datetime(2024, 12, 31, 23, 59, 59, tzinfo=timezone.utc),
        ),
    ],
)
def test_parse_created_valid(input_str, expected_date):
    result = parse_created(input_str)
    assert result == expected_date
    assert result.tzinfo == timezone.utc


@pytest.mark.parametrize(
    "input_str",
    [
        "2023-05-01 12:30:45",  # wrong format (space instead of T)
        "not-a-date",
        "2023/05/01T12:30:45",
        "2023-13-01T12:30:45",  # invalid month
    ],
)
def test_parse_created_invalid(input_str):
    with pytest.raises(argparse.ArgumentTypeError):
        parse_created(input_str)


@pytest.mark.parametrize(
    "input_str, expected_dict",
    [
        ("author=dogesec", {"source_name": "author", "external_id": "dogesec"}),
        ("key=value", {"source_name": "key", "external_id": "value"}),
        ("source_name=12345", {"source_name": "source_name", "external_id": "12345"}),
    ],
)
def test_parse_ref_valid(input_str, expected_dict):
    result = parse_ref(input_str)
    assert result == expected_dict


@pytest.mark.parametrize(
    "input_str",
    [
        "noequalsign",
        "",
        "novalue=",
        "=nokey",
    ],
)
def test_parse_ref_invalid(input_str):
    with pytest.raises(argparse.ArgumentTypeError):
        parse_ref(input_str)


@pytest.mark.parametrize(
    "input_str",
    [
        "custom.label1",
        "a.b",
        "namespace.tag123",
        "tlp.green",  # Should raise because tlp is unsupported
    ],
)
def test_parse_label_valid_and_unsupported(input_str):
    if input_str.startswith("tlp."):
        with pytest.raises(argparse.ArgumentTypeError):
            parse_label(input_str)
    else:
        assert parse_label(input_str) == input_str


@pytest.mark.parametrize(
    "input_str",
    [
        "invalid-label",
        "123",
        "justtext",
        "wrong_format",
    ],
)
def test_parse_label_invalid_format(input_str):
    with pytest.raises(argparse.ArgumentTypeError):
        parse_label(input_str)


@patch("txt2detection.__main__.parse_model")
def test_parse_args_file_mode_with_minimal(parse_model, monkeypatch):
    # We patch sys.argv to simulate CLI arguments
    ai_provider = "openai"
    monkeypatch.setattr(
        sys,
        "argv",
        ["prog", "file", "--name", "testname", "--ai_provider", ai_provider],
    )

    args = parse_args()
    parse_model.assert_called_once_with(ai_provider)
    assert args.mode == "file"
    assert args.name == "testname"
    assert args.ai_provider == parse_model.return_value
    assert hasattr(args, "input_text")
    # report_id should be set automatically
    assert hasattr(args, "report_id")


@patch("txt2detection.__main__.parse_model")
def test_parse_args_text_mode_requires_ai_provider(parse_model, monkeypatch):
    monkeypatch.setattr(
        sys, "argv", ["prog", "text", "--name", "test", "--ai_provider", "openai"]
    )
    args = parse_args()
    parse_model.assert_called_once_with("openai")
    assert args.mode == "text"
    assert args.ai_provider is not None
    assert hasattr(args, "report_id")


def test_parse_args_sigma_mode_no_ai_provider(monkeypatch):
    monkeypatch.setattr(sys, "argv", ["prog", "sigma", "--name", "test"])
    args = parse_args()
    assert args.mode == "sigma"
    # no ai_provider required in sigma mode
    assert getattr(args, "ai_provider", None) is None
    assert hasattr(args, "report_id")
    assert hasattr(args, "sigma_file")


def test_parse_args_check_credentials(monkeypatch):
    monkeypatch.setattr(sys, "argv", ["prog", "check-credentials"])
    with pytest.raises(SystemExit):
        parse_args()


@pytest.fixture
def args(tmp_path):
    """Fake Args object."""

    class Args:
        report_id = "test123"
        use_identity = "id-456"
        other_param = "value"

    return Args()


@pytest.fixture
def fake_bundler(bundler_instance):
    bundler_instance.data.navigator_layer = {
        "abc123": {"nav": "layer"},
        "def145": {"nothing": "to see here"},
    }
    bundler_instance.bundle.objects.extend(
        [
            {
                "type": "indicator",
                "pattern_type": "sigma",
                "id": "indicator--abc123",
                "pattern": "sigma: rule content",
            },
            {
                "type": "indicator",
                "pattern_type": "not-sigma",
                "id": "indicator--ignored-not-sigma",
                "pattern": "ignored",
            },
            {
                "type": "indicator",
                "pattern_type": "sigma",
                "id": "indicator--def145",
                "pattern": "sigma: rule content",
            },
        ]
    )
    return bundler_instance


@patch("txt2detection.__main__.setLogFile")
@patch("txt2detection.__main__.run_txt2detection")
def test_main_happy_path(
    mock_run, mock_setlog, args, fake_bundler, tmp_path, monkeypatch
):
    mock_run.return_value = fake_bundler
    monkeypatch.chdir(tmp_path)

    main(args)

    mock_setlog.assert_called_once()

    called_kwargs = mock_run.call_args.kwargs
    assert called_kwargs["identity"] == args.use_identity

    out_dir = Path(f"./output/{fake_bundler.bundle.id}")
    assert (out_dir / "bundle.json").exists()
    assert (out_dir / "data.json").exists()

    rule_file = out_dir / "rules/rule--abc123.yml"
    nav_file = out_dir / "rules/attack-enterprise-navigator-layer-rule--abc123.json"
    assert rule_file.read_text() == "sigma: rule content"
    assert json.loads(nav_file.read_text()) == {"nav": "layer"}
    nav_file2 = out_dir / "rules/attack-enterprise-navigator-layer-rule--def145.json"
    print(os.listdir(nav_file2.parent))
    assert json.loads(nav_file2.read_text()) == {"nothing": "to see here"}


@patch("txt2detection.__main__.setLogFile")
@patch("txt2detection.__main__.run_txt2detection", side_effect=ValueError("invalid"))
def test_main_valueerror_exit(mock_run, mock_setlog, args, tmp_path, monkeypatch):
    """Ensure ValueError causes sys.exit(19)."""
    monkeypatch.chdir(tmp_path)

    with pytest.raises(SystemExit) as e:
        main(args)
        assert e.value == 19


@patch("txt2detection.__main__.setLogFile")
@patch("txt2detection.__main__.run_txt2detection")
def test_main_validationerror_exit(mock_run, mock_setlog, args, tmp_path, monkeypatch):
    """Ensure ValidationError is logged and exits."""

    mock_run.side_effect = ValidationError("title", [])
    monkeypatch.chdir(tmp_path)

    with pytest.raises(SystemExit), patch("logging.error") as mock_error:
        main(args)
        mock_error.assert_any_call("Validate sigma file failed: validation failed")
