from pathlib import Path
from types import SimpleNamespace
import yaml
from .ai_extractor import ALL_AI_EXTRACTORS, BaseAIExtractor
from importlib import resources
import txt2detection
import logging

class DetectionLanguage(SimpleNamespace):
    pass

def load_detection_languages(path = Path("config/detection_languages.yaml")):
    if not path.exists():
        path = resources.files(txt2detection) / "config/detection_languages.yaml"
    langs = {}
    for k, v in yaml.safe_load(path.open()).items():
        v["slug"] = k
        langs[k] = DetectionLanguage(**v)
    return langs

def parse_model(value: str):
    splits = value.split(':', 1)
    provider = splits[0]
    if provider not in ALL_AI_EXTRACTORS:
        raise NotImplementedError(f"invalid AI provider in `{value}`, must be one of [{list(ALL_AI_EXTRACTORS)}]")
    provider = ALL_AI_EXTRACTORS[provider]
    if len(splits) == 2:
        return provider(model=splits[1])
    return provider()



def validate_token_count(max_tokens, input, extractor: BaseAIExtractor):
    logging.info('INPUT_TOKEN_LIMIT = %d', max_tokens)
    token_count = extractor.count_tokens(input)
    logging.info('TOKEN COUNT FOR %s: %d', extractor.extractor_name, token_count)
    if  token_count > max_tokens:
        raise Exception(f"{extractor.extractor_name}: input_file token count ({token_count}) exceeds INPUT_TOKEN_LIMIT ({max_tokens})")