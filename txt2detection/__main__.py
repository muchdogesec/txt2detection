import argparse
from datetime import datetime

from dataclasses import dataclass
from functools import partial
from itertools import chain
import json
import os
from pathlib import Path
import logging
import re
import sys
import uuid
from stix2 import Identity, parse as parse_stix

from txt2detection.ai_extractor.base import BaseAIExtractor
from txt2detection.utils import validate_token_count

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
import shutil


from .utils import STATUSES, valid_licenses, parse_model

def parse_identity(str):
    return Identity(**json.loads(str))

@dataclass
class Args:
    input_file: str
    input_text: str
    name: str
    tlp_level: str
    labels: list[str]
    created: datetime
    use_identity: Identity
    ai_provider: BaseAIExtractor
    report_id: uuid.UUID
    external_refs: dict[str, str]
    confidence: int
    reference_urls: list[str]
    status: str

def parse_created(value):
    """Convert the created timestamp to a datetime object."""
    try:
        return datetime.strptime(value, '%Y-%m-%dT%H:%M:%S')
    except ValueError:
        raise argparse.ArgumentTypeError("Invalid date format. Use YYYY-MM-DDTHH:MM:SS.")


def parse_ref(value):
    m = re.compile(r'(.+?)=(.+)').match(value)
    if not m:
        raise argparse.ArgumentTypeError("must be in format key=value")
    return dict(source_name=m.group(1), external_id=m.group(2))

def parse_args():
    parser = argparse.ArgumentParser(description='Convert text file to detection format.')
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--input_file', help='The file to be converted. Must be .txt', type=lambda x: Path(x).read_text())
    group.add_argument('--input_text', help='The text to be converted')
    parser.add_argument('--report_id', type=uuid.UUID, help='report_id to use for generated report')
    parser.add_argument('--name', required=True, help='Name of file, max 72 chars. Will be used in the STIX Report Object created.')
    parser.add_argument('--tlp_level', choices=['clear', 'green', 'amber', 'amber_strict', 'red'], default='clear', 
            help='Options are clear, green, amber, amber_strict, red. Default is clear if not passed.')
    parser.add_argument('--confidence', help='report confidence', type=int, default=None)
    parser.add_argument('--labels', type=lambda s: s.split(','), 
            help='Comma-separated list of labels. Case-insensitive (will be converted to lower-case). Allowed a-z, 0-9.')
    parser.add_argument('--created', type=parse_created, 
            help='Explicitly set created time in format YYYY-MM-DDTHH:MM:SS.sssZ. Default is current time.')
    parser.add_argument('--use_identity', type=parse_identity,
            help='Pass a full STIX 2.1 identity object (properly escaped). Validated by the STIX2 library. Default is SIEM Rules identity.')
    parser.add_argument("--ai_provider", required=True, type=parse_model, help="(required): defines the `provider:model` to be used. Select one option.", metavar="provider[:model]")
    parser.add_argument("--external_refs", type=parse_ref, help="pass additional `external_references` entry (or entries) to the report object created. e.g --external_ref author=dogesec link=https://dkjjadhdaj.net", default=[], metavar="{source_name}={external_id}", action="extend", nargs='+')
    parser.add_argument("--reference_urls", help="pass additional `external_references` url entry (or entries) to the report object created.", default=[], metavar="{url}", action="extend", nargs='+')
    parser.add_argument("--license", help="Valid SPDX license for the rule", default=None, metavar="[LICENSE]", choices=valid_licenses())
    parser.add_argument("--status", default='experimental', help="valid status for the sigma rule", metavar="sigma status", choices=STATUSES)

    args: Args = parser.parse_args()
    
    if args.created is None:
        args.created = datetime.now()

    args.input_text = args.input_text or args.input_file

    if not args.report_id:
        args.report_id = Bundler.generate_report_id(args.use_identity.id if args.use_identity else None, args.created, args.name)

    return args


def run_txt2detection(name, identity, tlp_level, input_text, confidence, labels, report_id, ai_provider: BaseAIExtractor, **kwargs) -> Bundler:
    status = kwargs.setdefault('status', 'experimental')
    assert status in STATUSES, f"status must be one of {STATUSES}"
    validate_token_count(int(os.getenv('INPUT_TOKEN_LIMIT', 0)), input_text, ai_provider)
    bundler = Bundler(name, identity, tlp_level, input_text, confidence, labels, report_id=report_id, **kwargs)
    detections = ai_provider.get_detections(input_text)
    bundler.bundle_detections(detections)
    return bundler

    
def main(args: Args):

    setLogFile(logging.root, Path(f"logs/log-{args.report_id}.log"))
    kwargs = args.__dict__
    kwargs['identity'] = args.use_identity
    # bundler = run_txt2detection(args.name, args.use_identity, args.tlp_level, args.input_text, args.confidence, args.labels, args.report_id, args.ai_provider, **kwargs)
    bundler = run_txt2detection(**kwargs)

    output_dir = Path("./output")/str(bundler.bundle.id)
    shutil.rmtree(output_dir, ignore_errors=True)
    rules_dir = output_dir/"rules"
    rules_dir.mkdir(exist_ok=True, parents=True)


    output_path = output_dir/'bundle.json'
    data_path = output_dir/f"data.json"
    output_path.write_text(bundler.to_json())
    data_path.write_text(bundler.detections.model_dump_json(indent=4))
    for obj in bundler.bundle['objects']:
        if obj['type'] != 'indicator' or obj['pattern_type'] != 'sigma':
            continue
        name = obj['id'].replace('indicator', 'rule') + '.yml'
        (rules_dir/name).write_text(obj['pattern'])
    logging.info(f"Writing bundle output to `{output_path}`")
