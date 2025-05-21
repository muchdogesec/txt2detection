import enum
import json
import re
import typing
import uuid
from slugify import slugify
from datetime import date as dt_date
from typing import Any, List, Literal, Optional, Union
from uuid import UUID

import jsonschema
from pydantic import BaseModel, Field, computed_field, field_validator
from pydantic_core import PydanticCustomError, core_schema
import yaml

from stix2 import (
    MarkingDefinition,
)

if typing.TYPE_CHECKING:
    from txt2detection.bundler import Bundler

UUID_NAMESPACE = uuid.UUID("a4d70b75-6f4a-5d19-9137-da863edd33d7")

TAG_PATTERN = re.compile(r"^[a-z0-9_-]+\.[a-z0-9._-]+$")

MITRE_TACTIC_MAP = {
    "initial-access": "TA0001",
    "execution": "TA0002",
    "persistence": "TA0003",
    "privilege-escalation": "TA0004",
    "defense-evasion": "TA0005",
    "credential-access": "TA0006",
    "discovery": "TA0007",
    "lateral-movement": "TA0008",
    "collection": "TA0009",
    "exfiltration": "TA0010",
    "command-and-control": "TA0011",
    "impact": "TA0040",
}


class TLP_LEVEL(enum.Enum):
    CLEAR = MarkingDefinition(
        spec_version="2.1",
        id="marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
        created="2022-10-01T00:00:00.000Z",
        definition_type="TLP:CLEAR",
        extensions={
            "extension-definition--60a3c5c5-0d10-413e-aab3-9e08dde9e88d": {
                "extension_type": "property-extension",
                "tlp_2_0": "clear",
            }
        },
    )
    GREEN = MarkingDefinition(
        spec_version="2.1",
        id="marking-definition--bab4a63c-aed9-4cf5-a766-dfca5abac2bb",
        created="2022-10-01T00:00:00.000Z",
        definition_type="TLP:GREEN",
        extensions={
            "extension-definition--60a3c5c5-0d10-413e-aab3-9e08dde9e88d": {
                "extension_type": "property-extension",
                "tlp_2_0": "green",
            }
        },
    )
    AMBER = MarkingDefinition(
        spec_version="2.1",
        id="marking-definition--55d920b0-5e8b-4f79-9ee9-91f868d9b421",
        created="2022-10-01T00:00:00.000Z",
        definition_type="TLP:AMBER",
        extensions={
            "extension-definition--60a3c5c5-0d10-413e-aab3-9e08dde9e88d": {
                "extension_type": "property-extension",
                "tlp_2_0": "amber",
            }
        },
    )
    AMBER_STRICT = MarkingDefinition(
        spec_version="2.1",
        id="marking-definition--939a9414-2ddd-4d32-a0cd-375ea402b003",
        created="2022-10-01T00:00:00.000Z",
        definition_type="TLP:AMBER+STRICT",
        extensions={
            "extension-definition--60a3c5c5-0d10-413e-aab3-9e08dde9e88d": {
                "extension_type": "property-extension",
                "tlp_2_0": "amber+strict",
            }
        },
    )
    RED = MarkingDefinition(
        spec_version="2.1",
        id="marking-definition--e828b379-4e03-4974-9ac4-e53a884c97c1",
        created="2022-10-01T00:00:00.000Z",
        definition_type="TLP:RED",
        extensions={
            "extension-definition--60a3c5c5-0d10-413e-aab3-9e08dde9e88d": {
                "extension_type": "property-extension",
                "tlp_2_0": "red",
            }
        },
    )

    @classmethod
    def levels(cls):
        return dict(
            clear=cls.CLEAR,
            green=cls.GREEN,
            amber=cls.AMBER,
            amber_strict=cls.AMBER_STRICT,
            red=cls.RED,
        )

    @classmethod
    def values(cls):
        return [
            cls.CLEAR.value,
            cls.GREEN.value,
            cls.AMBER.value,
            cls.AMBER_STRICT.value,
            cls.RED.value,
        ]

    @classmethod
    def get(cls, level: 'str|TLP_LEVEL'):
        if isinstance(level, cls):
            return level
        level = level.lower()
        level = level.replace('+', '_').replace('-', '_')
        if level not in cls.levels():
            raise Exception(f"unsupported tlp level: `{level}`")
        return cls.levels()[level]

    @property
    def name(self):
        return super().name.lower()

class Statuses(enum.StrEnum):
    stable = enum.auto()
    test = enum.auto()
    experimental = enum.auto()
    deprecated = enum.auto()
    unsupported = enum.auto()

class Level(enum.StrEnum):
    informational = enum.auto()
    low = enum.auto()
    medium = enum.auto()
    high = enum.auto()
    critical = enum.auto()

class SigmaTag(str):
    @classmethod
    def __get_pydantic_core_schema__(
        cls,
        _source: type[Any],
        _handler,
    ) -> core_schema.CoreSchema:
        return core_schema.no_info_after_validator_function(cls._validate, core_schema.str_schema())

    @classmethod
    def __get_pydantic_json_schema__(
        cls, core_schema: core_schema.CoreSchema, handler
    ):
        field_schema = handler(core_schema)
        field_schema.update(type='string', pattern=TAG_PATTERN.pattern, format='sigma-tag')
        return field_schema

    @classmethod
    def _validate(cls, input_value: str, /) -> str:
        if not TAG_PATTERN.match(input_value):
            raise PydanticCustomError(
            'value_error',
            'value is not a valid SIGMA tag: {reason}',
            {'reason': f'Must be in format namespace.value and match pattern {TAG_PATTERN.pattern}'},
        )
        return input_value
    
class RelatedRule(BaseModel):
    id: UUID
    type: Literal[
        "derived", "obsolete", "merged", "renamed", "similar"
    ]

class BaseDetection(BaseModel):
    title: str
    description: str
    detection: dict
    logsource: dict
    status: Statuses = Statuses.experimental
    falsepositives: list[str]
    tags: list[str]
    level: Level
    _custom_id = None
    _extra_data: dict

    def model_post_init(self, __context):
        self.tags = self.tags or []
        self._extra_data = dict()
        return super().model_post_init(__context)

    @property
    def detection_id(self):
        return str(self._custom_id or getattr(self, "id", None) or uuid.uuid4())

    @detection_id.setter
    def detection_id(self, custom_id):
        self._custom_id = custom_id.split("--")[-1]

    @property
    def tlp_level(self):
        return tlp_from_tags(self.tags)
    
    @tlp_level.setter
    def tlp_level(self, level):
        set_tlp_level_in_tags(self.tags, level)
    
    def set_labels(self, labels):
        self.tags.extend(labels)

    def set_extra_data_from_bundler(self, bundler: "Bundler"):
        raise NotImplementedError('this class should no longer be in use')


    def make_rule(self, bundler: "Bundler"):
        self.set_extra_data_from_bundler(bundler)
        self.tags = list(dict.fromkeys(self.tags))

        rule = dict(
            id=self.detection_id,
            **self.model_dump(
                exclude=["indicator_types", "id"], 
                mode="json",
                by_alias=True
            ),
        )
        for k, v in list(rule.items()):
            if not v:
                rule.pop(k, None)
                
        self.validate_rule_with_json_schema(rule)
        if getattr(self, 'date', 0):
            rule.update(date=self.date)
        if getattr(self, 'modified', 0):
            rule.update(modified=self.modified)
        return yaml.dump(rule, sort_keys=False, indent=4)

    def validate_rule_with_json_schema(self, rule):
        jsonschema.validate(
            rule,
            {
                "$ref": "https://github.com/SigmaHQ/sigma-specification/raw/refs/heads/main/json-schema/sigma-detection-rule-schema.json"
            },
        )
    
    @property
    def external_references(self):
        refs = []
        for attr in ['level', 'status', 'license']:
            if attr_val := getattr(self, attr, None):
                refs.append(dict(source_name=f'sigma-{attr}', description=attr_val))
        return refs

    @property
    def mitre_attack_ids(self):
        retval = []
        for label in self.tags:
            namespace, _, label_id = label.partition(".")
            if namespace == "attack":
                retval.append(MITRE_TACTIC_MAP.get(label_id, label_id.upper()))
        return retval

    @property
    def cve_ids(self):
        retval = []
        for label in self.tags:
            namespace, _, label_id = label.partition(".")
            if namespace == "cve":
                retval.append(namespace.upper() + "-" + label_id)
        return retval


class AIDetection(BaseDetection):
    indicator_types: list[str] = Field(default_factory=list)
    
    def to_sigma_rule_detection(self, bundler):
        rule_dict = {
            **self.model_dump(exclude=['indicator_types']),
            **dict(date=bundler.report.created.date(), modified=bundler.report.modified.date(), id=uuid.uuid4())
        }
        try:
            return SigmaRuleDetection.model_validate(rule_dict)
        except Exception as e:
            raise ValueError(dict(message='validate ai output failed', error=e, content=rule_dict))

class SigmaRuleDetection(BaseDetection):
    title: str
    id: Optional[UUID] = None
    related: Optional[list[RelatedRule]] = None
    name: Optional[str] = None
    taxonomy: Optional[str] = None
    status: Optional[Statuses] = None
    description: Optional[str] = None
    license: Optional[str] = None
    author: Optional[str] = None
    references: Optional[List[str]] = Field(default_factory=list)
    date: Optional["dt_date"] = Field(alias="date", default=None)
    modified: Optional["dt_date"] = None
    logsource: dict
    detection: dict
    fields: Optional[List[str]] = None
    falsepositives: Optional[List[str]] = None
    level: Optional[Level] = None
    tags: Optional[List[SigmaTag]] = Field(default_factory=[])
    scope: Optional[List[str]] = None
    _indicator_types: list = None

    @property
    def detection_id(self):
        return str(self.id)
    
    @property
    def indicator_types(self):
        return self._indicator_types
    
    @indicator_types.setter
    def indicator_types(self, types):
        self._indicator_types = types
    
    @detection_id.setter
    def detection_id(self, new_id):
        if self.id and str(self.id) != str(new_id):
            self.related = self.related or []
            self.related.append(RelatedRule(id=self.id, type="renamed"))
        self.id = new_id
    
    @field_validator('tags', mode='after')
    @classmethod
    def validate_tlp(cls, tags: list[str]):
        tlps = []
        for tag in tags:
            if tag.startswith('tlp.'):
                tlps.append(tag)
        if len(tlps) > 1:
            raise ValueError(f'tag must not contain more than one tag in tlp namespace. Got {tlps}')
        return tags
    
    @field_validator('modified', mode='after')
    @classmethod
    def validate_modified(cls, modified, info):
        if info.data.get('date') == modified:
            return None
        return modified
    
    def set_extra_data_from_bundler(self, bundler: "Bundler"):
        if not bundler:
            return
        
        if not self.date:
            from .utils import as_date
            self.date = as_date(bundler.created)
    
        self.set_labels(bundler.labels)
        self.tlp_level = bundler.tlp_level.name
        self.author = bundler.report.created_by_ref
        self.license = bundler.license
        self.references = bundler.reference_urls

class DetectionContainer(BaseModel):
    success: bool
    detections: list[Union[BaseDetection , AIDetection, SigmaRuleDetection]]



def tlp_from_tags(tags: list[SigmaTag]):
    for tag in tags:
        ns, _, level = tag.partition(".")
        if ns != "tlp":
            continue
        if tlp_level := TLP_LEVEL.get(level.replace("-", "_")):
            return tlp_level
    return None

def set_tlp_level_in_tags(tags: list[SigmaTag], level):
    level = str(level)
    for i, tag in enumerate(tags):
        if tag.startswith('tlp.'):
            tags.remove(tag)
    tags.append('tlp.'+level.replace("_", "-"))
    return tags
