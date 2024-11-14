import logging
from typing import Type
from llama_index.core.program import LLMTextCompletionProgram

import textwrap
from llama_index.core import PromptTemplate
from llama_index.core.llms.llm import LLM
import yaml

from .utils import ParserWithLogging, DetectionContainer
from llama_index.core.utils import get_tokenizer


_ai_extractor_registry: dict[str, 'Type[BaseAIExtractor]'] = {}
class BaseAIExtractor():
    llm: LLM
    system_prompt = (textwrap.dedent("""
    You are a cyber-security threat intelligence analysis tool responsible converting cyber security threat intelligence into detection rule.
    You have a deep understanding of cybersecurity concepts and threat intelligence.
    You are responsible for delivering computer-parsable output in JSON format. All output from you will be parsed with pydantic for further processing
    """))
    detection_template = PromptTemplate(textwrap.dedent(
        """
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
        ))
    

    def get_detections(self, input_text, log_sources, detection_language):
        logging.info('getting detections')
        return self.llm.structured_predict(
            prompt=self.detection_template,
            output_cls=DetectionContainer,
            input_str=input_text,
            log_sources=yaml.safe_dump(log_sources),
            detection_rule=detection_language,
        )
    
    def __init__(self, *args, **kwargs) -> None:
        pass

    def count_tokens(self, input_text):
        logging.info("unsupported model `%s`, estimating using llama-index's default tokenizer", self.extractor_name)
        return len(get_tokenizer()(input_text))
    
    def __init_subclass__(cls, /, provider, register=True, **kwargs):
        super().__init_subclass__(**kwargs)
        if register:
            cls.provider = provider
            _ai_extractor_registry[provider] = cls

    @property
    def extractor_name(self):
        return f"{self.provider}:{self.llm.model}"