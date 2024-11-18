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
    <persona>

        You are a cyber-security detection engineering tool responsible for analysing intelligence reports provided in text files and writing detection rules to detect the content being described in the reports.

        You have a deep understanding of cybersecurity tools like SIEMs and XDRs, as well as threat intelligence concepts.

        IMPORTANT: You must always deliver your work as a computer-parsable output in JSON format. All output from you will be parsed with pydantic for further processing.
        
    </persona>
    """))
    detection_template = PromptTemplate(textwrap.dedent(
        """

        <persona>

            You are a cyber-security detection engineering tool responsible for analysing intelligence reports provided in text files and writing detection rules to detect the content being described in the reports.

            You have a deep understanding of cybersecurity tools like SIEMs and XDRs, as well as threat intelligence concepts.

            IMPORTANT: You must always deliver your work as a computer-parsable output in JSON format. All output from you will be parsed with pydantic for further processing.
        
        </persona>

        <context>
            The threat intelligence report you are required to analyse for this job can be found between the `<input>` tags.

            This report can contain indicators of compromise, techniques, tactics or procedures of a threat.

            You need to comprehensively understand the threat intelligence provided, identifying indicators of compromise and behaviours.

        </context>

        <requirements>

            Using this understanding you should best determine the log sources that can be searched to identify what is being described. It is possible that the search spans multiple log sources, but at least one log source must be defined in the detection rule.

            By combining intelligence and log sources identified, create a {detection_rule.name} format. If you need help refer to the {detection_rule.name} documentation here {detection_rule.documentation}.

            It is possible that you create zero or more detection rules out of the input depending on the contents of the input.

            You need to document each detection rule clearly, outlining its purpose (as its name) and the logic and the specific TTP it addresses (as its `description`). You should also classify each rule with one or more `indicator_types` from the following list; 

            * `anomalous-activity`
            * `anonymization`
            * `benign`
            * `compromised`
            * `malicious-activity`
            * `attribution`
            * `unknown`
            
            Also, when relevant, you should add a list of MITRE ATT&CK Tactics, Techniques, or Sub-Techniques detected by this rule. You should print the ATT&CK IDs in the property `mitre_attack_ids`.        

        </requirements>

        <accuracy>

            Think about your answer first before you respond. The accuracy of your response is very important as this data will be used for operational purposes.

            If you don't know the answer, reply with success: false, do not ever try to make up an answer.

        </accuracy>

        <input>

        {input_str}
        
        </input>

        """
        ))
    

    def get_detections(self, input_text, detection_language):
        logging.info('getting detections')
        return self.llm.structured_predict(
            prompt=self.detection_template,
            output_cls=DetectionContainer,
            input_str=input_text,
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