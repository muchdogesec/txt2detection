import enum
import json
import re
import typing
import uuid
from slugify import slugify
from datetime import date
from typing import List, Optional
from uuid import UUID

import jsonschema
from pydantic import BaseModel, Field, computed_field
import yaml

from stix2 import (
    MarkingDefinition,
)

if typing.TYPE_CHECKING:    
    from txt2detection.bundler import Bundler

UUID_NAMESPACE = uuid.UUID('116f8cc9-4c31-490a-b26d-342627b12401')

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
    def get(cls, level):
        if isinstance(level, cls):
            return level
        if level not in cls.levels():
            raise Exception(f'unsupported tlp level: `{level}`')
        return cls.levels()[level]

    @property
    def name(self):
        return super().name.lower()




class BaseDetection(BaseModel):
    title: str
    description: str
    detection: dict
    logsource: dict
    falsepositives: list[str]
    tags: list[str]
    indicator_types: list[str] = Field(default_factory=list)
    confidence: int
    level: str
    _custom_id = None
    _bundler: 'Bundler'
    

    @property
    def rule(self):
        data = self.model_dump(exclude=["name", "indicator_types"])
        data.update(
            status="experimental",
            license="Apache-2.0",
            references="https://github.com/muchdogesec/txt2detection/",
            tags=self.tags + self.labels
        )
        return yaml.dump(data, sort_keys=False, indent=4)
    
    
    @property
    def detection_id(self):
        return str(self._custom_id or getattr(self, 'id', None) or uuid.uuid4())
    
    @detection_id.setter
    def detection_id(self, custom_id):
        self._custom_id = custom_id.split('--')[-1]

    @property
    def tlp_level(self):
        for tag in self.tags:
            ns, _, level = tag.partition('.')
            if ns != 'tlp':
                continue
            if tlp_level := TLP_LEVEL.get(level.replace('-', '_')):
                return tlp_level
        return None
    
    def make_rule(self, bundler: 'Bundler'):
        labels = bundler.labels
        rule = dict(id=self.detection_id, **self.model_dump(exclude=["indicator_types", "id"], mode='json'))
        rule.update(
            author=bundler.report.created_by_ref,
            status=bundler.indicator_status,
            license=bundler.license,
            references=bundler.reference_urls,
            tags=list(dict.fromkeys(['tlp.'+bundler.tlp_level.name.replace('_', '-')] + self.tags + [self.label_as_tag(label) for label in labels]))
        )
        for k, v in list(rule.items()):
            if not v:
                rule.pop(k, None)
        jsonschema.validate(rule, {'$ref': 'https://github.com/SigmaHQ/sigma-specification/raw/refs/heads/main/json-schema/sigma-detection-rule-schema.json'})
        return yaml.dump(rule, sort_keys=False, indent=4)
    
    @staticmethod
    def label_as_tag(label: str):
        label = label.lower()
        tag_pattern = re.compile(r"^[a-z0-9_-]+\.[a-z0-9._-]+$")
        no_ns_pattern = re.compile(r"^[a-z0-9._-]+$")
        if tag_pattern.match(label):
            return label
        elif no_ns_pattern.match(label):
            return 'txt2detection.'+label
        else:
            return 'txt2detection.'+slugify(label)
    
    @property
    def labels(self):
        labels = []
        for tag in self.tags:
            namespace, _, label = tag.partition(".")
            if namespace in ["attack", "cve", "tlp"]:
                continue
            labels.append(tag)
        return labels            

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

class Detection(BaseDetection):

    @computed_field(alias='date')
    @property
    def created(self) -> date:
        return self._bundler.report.created.date()
    
    @computed_field
    @property
    def modified(self) -> date:
        return self._bundler.report.modified.date()
    


class SigmaRule(BaseDetection):
    title: str
    id: Optional[UUID] = None
    related: Optional[list[dict]] = None
    name: Optional[str] = None
    taxonomy: Optional[str] = None
    status: Optional[str] = None
    description: Optional[str] = None
    license: Optional[str] = None
    author: Optional[str] = None
    references: Optional[List[str]] = None
    created: Optional['date'] = Field(alias='date', default=None)
    modified: Optional['date'] = None
    logsource: dict
    detection: dict
    fields: Optional[List[str]] = None
    falsepositives: Optional[List[str]] = None
    level: Optional[str] = None
    tags: Optional[List[str]] = None
    scope: Optional[List[str]] = None


    def model_post_init(self, __context):
        if self.id:
            sigma_id = self.id
            self.related = self.related or []
            self.related.append(dict(id=sigma_id, type='derived'))
            self.id = None
        return super().model_post_init(__context)



class DetectionContainer(BaseModel):
    success: bool
    detections: list[Detection]

