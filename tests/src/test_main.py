import sys
from unittest.mock import patch
import pytest
import argparse
from datetime import datetime, timezone

from txt2detection.__main__ import parse_created, parse_ref, parse_label, parse_args


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
