import argparse
from datetime import UTC, date, datetime

from dataclasses import dataclass
import io
import json
import os
from pathlib import Path
import logging
import re
import uuid
from stix2 import Identity
import yaml

from txt2detection.ai_extractor.base import BaseAIExtractor
from txt2detection.models import TAG_PATTERN, DetectionContainer, SigmaRuleDetection
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
    logger.info("=====================txt2detection======================")

from .bundler import Bundler
import shutil


from .utils import STATUSES, make_identity, valid_licenses, parse_model

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
    reference_urls: list[str]

def parse_created(value):
    """Convert the created timestamp to a datetime object."""
    try:
        return datetime.strptime(value, '%Y-%m-%dT%H:%M:%S').replace(tzinfo=UTC)
    except ValueError:
        raise argparse.ArgumentTypeError("Invalid date format. Use YYYY-MM-DDTHH:MM:SS.")


def parse_ref(value):
    m = re.compile(r'(.+?)=(.+)').match(value)
    if not m:
        raise argparse.ArgumentTypeError("must be in format key=value")
    return dict(source_name=m.group(1), external_id=m.group(2))

def parse_label(label: str):
    if not TAG_PATTERN.match(label):
        raise argparse.ArgumentTypeError("Invalid label format. Must follow sigma tag format {namespace}.{label}")
    namespace, _, _ = label.partition('.')
    if namespace in ['tlp']:
        raise argparse.ArgumentTypeError(f"Unsupported tag namespace `{namespace}`")
    return label

def parse_args():
    parser = argparse.ArgumentParser(description='Convert text file to detection format.')
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--input_file', help='The file to be converted. Must be .txt', type=lambda x: Path(x).read_text())
    group.add_argument('--input_text', help='The text to be converted')
    group.add_argument('--sigma_file', help='The sigma file to be converted. Must be .yml', type=lambda x: Path(x).read_text())
    parser.add_argument('--report_id', type=uuid.UUID, help='report_id to use for generated report')
    parser.add_argument('--name', required=True, help='Name of file, max 72 chars. Will be used in the STIX Report Object created.')
    parser.add_argument('--tlp_level', choices=['clear', 'green', 'amber', 'amber_strict', 'red'], default='clear', 
            help='Options are clear, green, amber, amber_strict, red. Default is clear if not passed.')
    parser.add_argument('--labels', type=parse_label, action="extend", nargs='+', 
            help='Comma-separated list of labels. Case-insensitive (will be converted to lower-case). Allowed a-z, 0-9.')
    parser.add_argument('--created', type=parse_created, 
            help='Explicitly set created time in format YYYY-MM-DDTHH:MM:SS.sssZ. Default is current time.')
    parser.add_argument('--use_identity', type=parse_identity,
            help='Pass a full STIX 2.1 identity object (properly escaped). Validated by the STIX2 library. Default is SIEM Rules identity.')
    parser.add_argument("--ai_provider", required=False, type=parse_model, help="(required): defines the `provider:model` to be used. Select one option.", metavar="provider[:model]")
    parser.add_argument("--external_refs", type=parse_ref, help="pass additional `external_references` entry (or entries) to the report object created. e.g --external_ref author=dogesec link=https://dkjjadhdaj.net", default=[], metavar="{source_name}={external_id}", action="extend", nargs='+')
    parser.add_argument("--reference_urls", help="pass additional `external_references` url entry (or entries) to the report object created.", default=[], metavar="{url}", action="extend", nargs='+')
    parser.add_argument("--license", help="Valid SPDX license for the rule", default=None, metavar="[LICENSE]", choices=valid_licenses())

    args: Args = parser.parse_args()
    
    if args.created is None:
        args.created = datetime.now()

    if not args.sigma_file:
        assert args.ai_provider, "--ai_provider is required in file or txt mode"
    args.input_text = args.input_text or args.input_file

    if not args.report_id:
        args.report_id = Bundler.generate_report_id(args.use_identity.id if args.use_identity else None, args.created, args.name)

    return args

def as_date(d: 'date|datetime'):
    if isinstance(d, datetime):
        return d.date()
    return d

def run_txt2detection(name, identity, tlp_level, input_text: str, labels: list[str], report_id: str|uuid.UUID, ai_provider: BaseAIExtractor, **kwargs) -> Bundler:
    if sigma := kwargs.get('sigma_file'):
        detection = get_sigma_detections(sigma)
        if not identity and detection.author:
            identity = make_identity(detection.author)
        kwargs.update(
            created=detection.date,
            modified=detection.modified,
            references=kwargs.setdefault('reference_urls', [])+detection.references
        )
        detection.date = as_date(detection.date or kwargs.get('created'))
        detection.modified = as_date(kwargs.setdefault('modified', detection.modified))
        detection.references = kwargs['references']
        detection.detection_id = str(report_id).removeprefix('report--')
        bundler = Bundler(name, identity, detection.tlp_level or tlp_level or 'clear', detection.description or "<SIGMA RULE>", (labels or [])+detection.labels, report_id=report_id, **kwargs)
        detections = DetectionContainer(success=True, detections=[])
        detections.detections.append(detection)
    else:
        validate_token_count(int(os.getenv('INPUT_TOKEN_LIMIT', 0)), input_text, ai_provider)
        bundler = Bundler(name, identity, tlp_level, input_text, labels, report_id=report_id, **kwargs)
        detections = ai_provider.get_detections(input_text)
    bundler.bundle_detections(detections)
    return bundler

def get_sigma_detections(sigma: str) -> SigmaRuleDetection:
    obj = yaml.safe_load(io.StringIO(sigma))
    return SigmaRuleDetection.model_validate(obj)
    

    
def main(args: Args):

    setLogFile(logging.root, Path(f"logs/log-{args.report_id}.log"))
    kwargs = args.__dict__
    kwargs['identity'] = args.use_identity
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
