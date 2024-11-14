import argparse
from datetime import datetime

from dataclasses import dataclass
from functools import partial
from itertools import chain
import os
from pathlib import Path
import logging
import sys

from txt2detection.ai_extractor.base import BaseAIExtractor

def configureLogging():
    # Configure logging
    stream_handler = logging.StreamHandler()  # Log to stdout and stderr
    stream_handler.setLevel(logging.INFO)
    logging.basicConfig(
        level=logging.DEBUG,  # Set the desired logging level
        format=f"%(asctime)s [%(levelname)s] %(message)s",
        handlers=[stream_handler],
        datefmt='%d-%b-%y %H:%M:%S'
    )

    return logging.root
configureLogging()

def setLogFile(logger, file: Path):
    file.parent.mkdir(parents=True, exist_ok=True)
    logger.info(f"Saving log to `{file.absolute()}`")
    handler = logging.FileHandler(file, "w")
    handler.formatter = logging.Formatter(fmt='%(levelname)s %(asctime)s - %(message)s', datefmt='%d-%b-%y %H:%M:%S')
    handler.setLevel(logging.DEBUG)
    logger.addHandler(handler)
    logger.info("=====================txt2stix======================")

from dotenv import load_dotenv
from .bundler import Bundler

from .utils import load_config, load_detection_languages, parse_model

@dataclass
class Args:
    input_file: str
    name: str
    tlp_level: str
    labels: list[str]
    created: datetime
    use_identity: str
    products_in_stack: str
    detection_language: str
    ai_provider: BaseAIExtractor

def parse_created(value):
    """Convert the created timestamp to a datetime object."""
    try:
        return datetime.strptime(value, '%Y-%m-%dT%H:%M:%S.%fZ')
    except ValueError:
        raise argparse.ArgumentTypeError("Invalid date format. Use YYYY-MM-DDTHH:MM:SS.sssZ.")
    
def parse_products(all_sources, value):
    log_sources = {}
    for k, source in all_sources.items():
        if source['product'] == value:
            log_sources[k] = source
    if not log_sources:
        raise argparse.ArgumentTypeError(f"invalid product `{value}`")
    return log_sources


def parse_args():
    log_sources = load_config()
    detection_languages = load_detection_languages()
    parser = argparse.ArgumentParser(description='Convert text file to detection format.')
    
    parser.add_argument('--input_file', required=True, help='The file to be converted. Must be .txt')
    parser.add_argument('--name', required=True, help='Name of file, max 72 chars. Will be used in the STIX Report Object created.')
    parser.add_argument('--tlp_level', choices=['clear', 'green', 'amber', 'amber_strict', 'red'], default='clear', 
            help='Options are clear, green, amber, amber_strict, red. Default is clear if not passed.')
    parser.add_argument('--labels', type=lambda s: s.split(','), 
            help='Comma-separated list of labels. Case-insensitive (will be converted to lower-case). Allowed a-z, 0-9.')
    parser.add_argument('--created', type=parse_created, 
            help='Explicitly set created time in format YYYY-MM-DDTHH:MM:SS.sssZ. Default is current time.')
    parser.add_argument('--use_identity', 
            help='Pass a full STIX 2.1 identity object (properly escaped). Validated by the STIX2 library. Default is SIEM Rules identity.')
    parser.add_argument('--products_in_stack', required=True, 
            help='Comma-separated list of products. Provides context for writing detection rules. Check config/logs.yaml for values.',
            type=partial(parse_products, log_sources), nargs='+',
        )
    parser.add_argument('--detection_language', required=True, 
            help='Detection rule language for the output. Check config/detection_languages.yaml for available keys.',
            choices=detection_languages.keys(),
        )
    parser.add_argument("--ai_provider", required=True, type=parse_model, help="(required): defines the `provider:model` to be used. Select one option.", metavar="provider[:model]")

    args: Args = parser.parse_args()
    args.detection_language = detection_languages[args.detection_language]
    args.products_in_stack = dict(chain(*map(dict.items, args.products_in_stack)))
    
    if args.created is None:
        args.created = datetime.now()

    if not os.path.isfile(args.input_file):
        parser.error(f"The specified input file does not exist: {args.input_file}")

    return args

def validate_token_count(max_tokens, input, extractor: BaseAIExtractor):
    logging.info('INPUT_TOKEN_LIMIT = %d', max_tokens)
    token_count = extractor.count_tokens(input)
    logging.info('TOKEN COUNT FOR %s: %d', extractor.extractor_name, token_count)
    if  token_count > max_tokens:
        raise Exception(f"{extractor.extractor_name}: input_file token count ({token_count}) exceeds INPUT_TOKEN_LIMIT ({max_tokens})")

    
def main(args: Args):
    setLogFile(logging.root, Path(f"logs/log-{int(args.created.timestamp())}.log"))
    input_str = Path(args.input_file).read_text()
    validate_token_count(int(os.getenv('INPUT_TOKEN_LIMIT', 0)), input_str, args.ai_provider)
    detections = args.ai_provider.get_detections(input_str, detection_language=args.detection_language, log_sources=args.products_in_stack)
    bundler = Bundler(args.name, args.detection_language.slug, args.use_identity, args.tlp_level, input_str, 0, args.labels)
    bundler.bundle_detections(detections)
    out = bundler.to_json()

    output_path = Path("./output")/f"{bundler.bundle.id}.json"
    output_path.parent.mkdir(exist_ok=True)
    output_path.write_text(out)
    logging.info(f"Writing bundle output to `{output_path}`")
