import argparse
from datetime import datetime

from dataclasses import dataclass
import os
from pathlib import Path
import logging

logging.basicConfig(level=logging.INFO)

from dotenv import load_dotenv
from .openai import run_prediction_openapi
from .bundler import Bundler

from .utils import load_config, load_detection_languages

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

def parse_created(value):
    """Convert the created timestamp to a datetime object."""
    try:
        return datetime.strptime(value, '%Y-%m-%dT%H:%M:%S.%fZ')
    except ValueError:
        raise argparse.ArgumentTypeError("Invalid date format. Use YYYY-MM-DDTHH:MM:SS.sssZ.")
    
def parse_products(value):
    products = [s.strip() for s in value.split(',')]
    all_sources = load_config()
    log_sources = {}
    for k, source in all_sources.items():
        if source['product'] in products:
            log_sources[k] = source
    if not log_sources:
        raise argparse.ArgumentTypeError("at least one log source is required")
    return log_sources


def parse_args():
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
            type=parse_products,
        )
    parser.add_argument('--detection_language', required=True, 
            help='Detection rule language for the output. Check config/detection_languages.yaml for available keys.',
            choices=detection_languages.keys(),
        )

    args = parser.parse_args()
    args.detection_language = detection_languages[args.detection_language]
    
    if args.created is None:
        args.created = datetime.now()

    if not os.path.isfile(args.input_file):
        parser.error(f"The specified input file does not exist: {args.input_file}")

    return args
    
def main(args: Args):
    input_str = Path(args.input_file).read_text()
    detections = run_prediction_openapi(input_str, detection_language=args.detection_language, log_sources=args.products_in_stack)
    bundler = Bundler(args.name, args.detection_language.slug, args.use_identity, args.tlp_level, input_str, 0, args.labels)
    bundler.bundle_detections(detections)
    out = bundler.to_json()
    print(out)
    print(detections)

    output_path = Path("./output")/f"{bundler.bundle.id}.json"
    output_path.parent.mkdir(exist_ok=True)
    output_path.write_text(out)
    logging.info(f"Writing bundle output to `{output_path}`")

if __name__ == '__main__':
    load_dotenv(override=True)
    parse_products('linux')
    args = parse_args()
    main(args)
