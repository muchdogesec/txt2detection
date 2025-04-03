import io
import json
import logging
import re
import typing
import uuid
from slugify import slugify

import dotenv
import textwrap

import jsonschema
from pydantic import BaseModel, Field
from llama_index.core.output_parsers import PydanticOutputParser
import yaml

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


class Detection(BaseModel):
    title: str
    description: str
    detection: dict
    logsource: dict
    falsepositives: list[str]
    tags: list[str]
    indicator_types: list[str]
    confidence: int
    _custom_id = None

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
    def id(self):
        return self._custom_id or str(
            uuid.uuid5(UUID_NAMESPACE, f"txt2detection+{self.title}+{json.dumps(self.detection)}")
        )
    
    @id.setter
    def id(self, custom_id):
        self._custom_id = custom_id.split('--')[-1]
    
    def make_rule(self, bundler: 'Bundler'):
        labels = bundler.labels
        rule = dict(id=self.id, **self.model_dump(exclude=["indicator_types"]))
        rule.update(
            author=bundler.report.created_by_ref,
            status="experimental",
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


class DetectionContainer(BaseModel):
    success: bool
    detections: list[Detection]


class ParserWithLogging(PydanticOutputParser):
    def parse(self, text: str):
        f = io.StringIO()
        print("\n" * 5 + "=================start=================", file=f)
        print(text, file=f)
        print("=================close=================" + "\n" * 5, file=f)
        logging.debug(f.getvalue())
        return super().parse(text)
