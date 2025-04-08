from datetime import datetime
from functools import lru_cache
from types import SimpleNamespace
import uuid
import requests
from .ai_extractor import ALL_AI_EXTRACTORS, BaseAIExtractor, ModelError
import logging

import enum
import logging
import requests
from stix2 import Identity

from .models import UUID_NAMESPACE


class DetectionLanguage(SimpleNamespace):
    pass

def parse_model(value: str):
    splits = value.split(':', 1)
    provider = splits[0]
    if provider not in ALL_AI_EXTRACTORS:
        raise NotImplementedError(f"invalid AI provider in `{value}`, must be one of {list(ALL_AI_EXTRACTORS)}")
    provider = ALL_AI_EXTRACTORS[provider]
    try:
        if len(splits) == 2:
            return provider(model=splits[1])
        return provider()
    except Exception as e:
        raise ModelError(f"Unable to initialize model `{value}`") from e

def make_identity(name):
    from .bundler import Bundler
    return Identity(id='identity--'+str(uuid.uuid5(UUID_NAMESPACE, f"txt2detection+{name}")), name=name, created_by_ref=Bundler.default_identity.id, created=datetime(2020, 1, 1), modified=datetime(2020, 1, 1))


def validate_token_count(max_tokens, input, extractor: BaseAIExtractor):
    logging.info('INPUT_TOKEN_LIMIT = %d', max_tokens)
    token_count = extractor.count_tokens(input)
    logging.info('TOKEN COUNT FOR %s: %d', extractor.extractor_name, token_count)
    if  token_count > max_tokens:
        raise Exception(f"{extractor.extractor_name}: input_file token count ({token_count}) exceeds INPUT_TOKEN_LIMIT ({max_tokens})")
    
def valid_licenses():
    @lru_cache(maxsize=5)
    def get_licenses(date):
        resp = requests.get("https://github.com/spdx/license-list-data/raw/refs/heads/main/json/licenses.json")
        return {l['licenseId']: l['name'] for l in resp.json()['licenses']}
    return get_licenses(datetime.now().date().isoformat())


STATUSES = ['stable', 'test', 'experimental', 'deprecated', 'unsupported']