import io
import logging

import dotenv
import textwrap

from pydantic import BaseModel, Field
from llama_index.core.output_parsers import PydanticOutputParser
import yaml

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

    @property
    def rule(self):
        data = self.model_dump(exclude=["name", "indicator_types"])
        data.update(
            status="experimental",
            license="Apache-2.0",
            references="https://github.com/muchdogesec/txt2detection/",
        )
        return yaml.dump(data, sort_keys=False, indent=4)

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
