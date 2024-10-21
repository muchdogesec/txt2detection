import os
from pathlib import Path
from types import SimpleNamespace
from typing import List
from pydantic import BaseModel, Field
from llama_index.core import SimpleDirectoryReader
from llama_index.core import response_synthesizers
from llama_index.llms.openai import OpenAI

# from llama_index.llms.openai import SyncOpenAI
from llama_index.core import PromptTemplate
from llama_index.core.output_parsers import PydanticOutputParser
import yaml

from .utils import DetectionLanguage


class Detection(BaseModel):
    name: str = Field(description="descriptive name for the detection", examples=["Unauthorized read", "Suspicious activity"])
    description: str
    rule: str = Field(description="express detecion rule in format described, escape properly.")
    indicator_types: list[str]
    mitre_attack_ids: list[str]


class DetectionContainer(BaseModel):
    success: bool
    detections: list[Detection]


template_str = """
<input>
{input_str}
</input>

<context>
You are a threat intelligence analyst tasked with converting cyber security threat intelligence into detection rule.

Your threat intelligence will be provided in the form of threat intelligence reports that describes the indicators of compromise, techniques, tactics or procedures of an adversary. This threat intelligence will be provided to you in the `<context>` tags as your input.

You need to comprehensively understand the threat intelligence provided, identifying indicators of compromise and behaviours.

The following log sources are what must be searched to identify the indicators of compromise and behaviours you identify:

{log_sources}

Using the the indicators of compromise and behaviours you identify and the structure of the logs needed to be searched, create a rule using {detection_rule.name} format. If you need help refer to the {detection_rule.name} documentation here {detection_rule.documentation}.
It is possible that you create zero or more detection rules.

You need to document each detection rule clearly, outlining its purpose (as its name) and the logic and the specific TTP it addresses (as its description). You should also classify each rule with one or more indicator_types from the following list; 

* anomalous-activity
* anonymization
* benign
* compromised
* malicious-activity
* attribution
* unknown

Also, when relevant, you should add a list of MITRE ATT&CK Tactics, Techniques, or Sub-Techniques detected by this rule. You should print the ATT&CK IDs in the property `mitre_attack_ids`.
</context>

<requirement>
Think about your answer first before you respond.

If you don't know the answer, just say that you don't know, don't try to make up an answer.
</requirement>

<style>
The response should be written in a clear, concise, and technical style, suitable for cybersecurity professionals. Use terminology and structures familiar to cybersecurity threat analysis and detection development.
</style>

<tone>
The tone should be objective and analytical, focusing on providing clear and factual information without unnecessary embellishments or subjective interpretations.
</tone>

<audience>
The intended audience is cybersecurity analysts and engineers who are responsible for creating new detections. They have a deep understanding of cybersecurity concepts, threat intelligence, and detection mechanisms.
</audience>
"""

output_parser = PydanticOutputParser(output_cls=DetectionContainer)
prompt_template = PromptTemplate(template_str)





def run_prediction_openapi(input_str, llm=OpenAI(), detection_language=None, log_sources=[]) -> DetectionContainer:
    llm.max_tokens = int(os.environ['INPUT_TOKEN_LIMIT'])
    llm.model = os.environ.get('OPENAI_MODEL', 'gpt-4o')
    if not isinstance(detection_language, DetectionLanguage):
        raise Exception("Invalid detection language")
    if not log_sources:
        raise Exception("expected at least one log source")
    return llm.structured_predict(
        prompt=prompt_template,
        output_cls=DetectionContainer,
        input_str=input_str,
        log_sources=yaml.safe_dump(log_sources),
        detection_rule=detection_language
    )
