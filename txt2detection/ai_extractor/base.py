import logging
from typing import Type
from llama_index.core.program import LLMTextCompletionProgram

import textwrap
from llama_index.core.llms.llm import LLM

from txt2detection.ai_extractor import prompts

from txt2detection.ai_extractor.utils import ParserWithLogging
from txt2detection.models import DetectionContainer, DetectionContainer
from llama_index.core.utils import get_tokenizer


_ai_extractor_registry: dict[str, 'Type[BaseAIExtractor]'] = {}
class BaseAIExtractor():
    llm: LLM
    system_prompt = (textwrap.dedent("""
    <persona>

        You are a cyber-security detection engineering tool responsible for analysing intelligence reports provided in text files and writing SIGMA detection rules to detect the content being described in the reports.

        You have a deep understanding of cybersecurity tools like SIEMs and XDRs, as well as threat intelligence concepts.

        IMPORTANT: You must always deliver your work as a computer-parsable output in JSON format. All output from you will be parsed with pydantic for further processing.
        
    </persona>
    """))
    

    def get_detections(self, input_text) -> DetectionContainer:
        logging.info('getting detections')


        return LLMTextCompletionProgram.from_defaults(
            output_parser=ParserWithLogging(DetectionContainer),
            prompt=prompts.SIEMRULES_PROMPT,
            verbose=True,
            llm=self.llm,
        )(document=input_text)
    
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