import logging

import dotenv

from .base import _ai_extractor_registry as ALL_AI_EXTRACTORS

from .base import BaseAIExtractor

for path in ["openai", "anthropic", "gemini"]:
    try:
        __import__(__package__ + "." + path)
    except Exception as e:
        logging.warning("%s not installed", path, exc_info=True)