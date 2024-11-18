import io
import logging

import dotenv
import textwrap

from pydantic import BaseModel, Field
from llama_index.core.output_parsers import PydanticOutputParser


class Detection(BaseModel):
    name: str = Field(description="A descriptive name for the detection rule", examples=["Unauthorized read", "Suspicious activity"])
    description: str
    rule: str = Field(description="The detection rule in format described, escape properly.")
    indicator_types: list[str]
    mitre_attack_ids: list[str]


class DetectionContainer(BaseModel):
    success: bool
    detections: list[Detection]

class ParserWithLogging(PydanticOutputParser):
    def parse(self, text: str):
        f = io.StringIO()
        print("\n"*5 + "=================start=================", file=f)
        print(text, file=f)
        print("=================close=================" + "\n"*5, file=f)
        logging.debug(f.getvalue())
        return super().parse(text)
