from pathlib import Path
from types import SimpleNamespace
import yaml


class DetectionLanguage(SimpleNamespace):
    pass



def load_config():
    log_sources = {}
    for k, v in yaml.safe_load(Path("config/logs.yaml").open()).items():
        log_sources[k] = v
    return log_sources

def load_detection_languages():
    langs = {}
    for k, v in yaml.safe_load(Path("config/detection_languages.yaml").open()).items():
        v["slug"] = k
        langs[k] = DetectionLanguage(**v)
    return langs