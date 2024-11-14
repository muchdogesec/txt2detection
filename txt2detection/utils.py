from pathlib import Path
from types import SimpleNamespace
import yaml
from .ai_extractor import ALL_AI_EXTRACTORS

class DetectionLanguage(SimpleNamespace):
    pass



def load_config():
    log_sources = {}
    for k, v in yaml.safe_load(Path("config/logs.yaml").open()).items():
        v['slug'] = k
        log_sources[k] = v
    return log_sources

def load_detection_languages():
    langs = {}
    for k, v in yaml.safe_load(Path("config/detection_languages.yaml").open()).items():
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