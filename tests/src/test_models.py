import pytest
import uuid
from datetime import date as dt_date

from txt2detection.models import (
    TLP_LEVEL,
    SigmaTag,
    tlp_from_tags,
    set_tlp_level_in_tags,
    BaseDetection,
    SigmaRuleDetection,
    Level,
    Statuses,
)


# -----------------------
# TLP LEVEL
# -----------------------
@pytest.mark.parametrize(
    "input_level,expected_enum",
    [
        ("clear", TLP_LEVEL.CLEAR),
        ("green", TLP_LEVEL.GREEN),
        ("amber", TLP_LEVEL.AMBER),
        ("amber-strict", TLP_LEVEL.AMBER_STRICT),
        ("amber+strict", TLP_LEVEL.AMBER_STRICT),
        ("red", TLP_LEVEL.RED),
        (TLP_LEVEL.GREEN, TLP_LEVEL.GREEN),
    ],
)
def test_tlp_get(input_level, expected_enum):
    assert TLP_LEVEL.get(input_level) == expected_enum


def test_tlp_invalid():
    with pytest.raises(Exception, match="unsupported tlp level"):
        TLP_LEVEL.get("purple")


# -----------------------
# SigmaTag
# -----------------------
@pytest.mark.parametrize(
    "valid_tag",
    [
        "attack.execution",
        "cve.2021-1234",
        "tlp.red",
    ],
)
def test_sigma_tag_valid(valid_tag):
    assert SigmaTag._validate(valid_tag) == valid_tag


@pytest.mark.parametrize(
    "invalid_tag",
    [
        "InvalidTag",
        "justtext",
        "tlp+red",
    ],
)
def test_sigma_tag_invalid(invalid_tag):
    with pytest.raises(Exception):
        SigmaTag._validate(invalid_tag)


# -----------------------
# TLP from/set tags
# -----------------------
def test_tlp_from_tags():
    tags = [SigmaTag("tlp.red")]
    result = tlp_from_tags(tags)
    assert result == TLP_LEVEL.RED


def test_set_tlp_level_in_tags_replaces_old():
    tags = [SigmaTag("tlp.green"), SigmaTag("something.else")]
    new_tags = set_tlp_level_in_tags(tags, "amber")
    assert "tlp.amber" in new_tags
    assert "tlp.green" not in new_tags


# -----------------------
# BaseDetection.detection_id logic
# -----------------------
def test_detection_id_setter_and_getter():
    det = BaseDetection(
        title="Test",
        description="Desc",
        detection={},
        logsource={},
        falsepositives=[],
        tags=[],
        level=Level.low,
    )
    custom_id = f"prefix--{uuid.uuid4()}"
    det.detection_id = custom_id
    assert det.detection_id == custom_id.split("--")[-1]


# -----------------------
# BaseDetection.tlp_level
# -----------------------
def test_tlp_level_property():
    det = BaseDetection(
        title="Test",
        description="Desc",
        detection={},
        logsource={},
        falsepositives=[],
        tags=["tlp.green"],
        level=Level.low,
    )
    assert det.tlp_level == TLP_LEVEL.GREEN
    det.tlp_level = "red"
    assert "tlp.red" in det.tags
    assert "tlp.green" not in det.tags


# -----------------------
# SigmaRuleDetection.validate_tlp
# -----------------------
def test_validate_tlp_accepts_single():
    tags = ["tlp.green", "attack.discovery"]
    result = SigmaRuleDetection.validate_tlp(tags)
    assert result == tags


def test_validate_tlp_rejects_multiple():
    with pytest.raises(ValueError, match="more than one tag in tlp namespace"):
        SigmaRuleDetection.validate_tlp(["tlp.red", "tlp.green"])


# -----------------------
# SigmaRuleDetection.validate_modified
# -----------------------
def test_validate_modified_same_as_date():
    date = dt_date(2024, 5, 1)
    assert (
        SigmaRuleDetection.validate_modified(
            date, info=type("obj", (), {"data": {"date": date}})
        )
        is None
    )


def test_validate_modified_diff_from_date():
    date = dt_date(2024, 5, 1)
    modified = dt_date(2024, 5, 2)
    assert (
        SigmaRuleDetection.validate_modified(
            modified, info=type("obj", (), {"data": {"date": date}})
        )
        == modified
    )


# -----------------------
# BaseDetection.mitre_attack_ids / cve_ids
# -----------------------
def test_mitre_attack_ids_and_cve_ids():
    det = BaseDetection(
        title="Test",
        description="Desc",
        detection={},
        logsource={},
        falsepositives=[],
        tags=["attack.execution", "cve.2021-1234", "attack.t123"],
        level=Level.medium,
    )
    assert det.mitre_attack_ids == ["TA0002", "T123"]
    assert det.cve_ids == ["CVE-2021-1234"]


# -----------------------
# SigmaRuleDetection.detection_id mutation
# -----------------------
def test_sigma_detection_id_tracks_renamed():
    id1 = uuid.uuid4()
    id2 = uuid.uuid4()
    det = SigmaRuleDetection(
        title="Test", id=id1, detection={}, logsource={}, tags=[], level=Level.low
    )
    det.detection_id = str(id2)
    assert str(det.id) == str(id2)
    assert len(det.related) == 1
    assert det.related[0].type == "renamed"
    assert det.related[0].id == id1


# -----------------------
# BaseDetection.external_references
# -----------------------
@pytest.mark.parametrize(
    "level,status,license_,expected_refs",
    [
        (
            Level.critical,
            Statuses.stable,
            "MIT",
            [
                {"source_name": "sigma-level", "description": Level.critical},
                {"source_name": "sigma-status", "description": Statuses.stable},
                {"source_name": "sigma-license", "description": "MIT"},
            ],
        ),
        (
            Level.medium,
            None,
            None,
            [
                {"source_name": "sigma-level", "description": Level.medium},
            ],
        ),
        (
            None,
            None,
            None,
            [],
        ),
    ],
)
def test_external_references_generated(level, status, license_, expected_refs):
    detection = SigmaRuleDetection(
        title="External Ref Test",
        detection={"selection": {"field": "value"}},
        logsource={"category": "process_creation"},
        tags=[],
        falsepositives=[],
        id=uuid.uuid4(),
        level=level,
        status=status,
        license=license_,
    )

    assert detection.external_references == expected_refs
