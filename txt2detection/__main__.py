import argparse
from datetime import UTC, datetime

from dataclasses import dataclass
import io
import json
import os
from pathlib import Path
import logging
import re
import sys
import uuid
from stix2 import Identity
import yaml

from txt2detection.ai_extractor.base import BaseAIExtractor
from txt2detection.models import TAG_PATTERN, DetectionContainer, Level, SigmaRuleDetection
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


from .utils import STATUSES, as_date, make_identity, valid_licenses, parse_model

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
    mode = parser.add_subparsers(title='process-mode', dest='mode', description="mode to use")
    file = mode.add_parser('file', help="process a file input using ai")
    text = mode.add_parser('text', help="process a text argument using ai")
    sigma = mode.add_parser('sigma', help="process a sigma file without ai")

    for mode_parser in [file, text, sigma]:
        mode_parser.add_argument('--report_id', type=uuid.UUID, help='report_id to use for generated report')
        mode_parser.add_argument('--name', required=True, help='Name of file, max 72 chars. Will be used in the STIX Report Object created.')
        mode_parser.add_argument('--tlp_level', choices=['clear', 'green', 'amber', 'amber_strict', 'red'],
                help='Options are clear, green, amber, amber_strict, red. Default is clear if not passed.')
        mode_parser.add_argument('--labels', type=parse_label, action="extend", nargs='+',
                help='Comma-separated list of labels. Case-insensitive (will be converted to lower-case). Allowed a-z, 0-9.')
        mode_parser.add_argument('--created', type=parse_created,
                help='Explicitly set created time in format YYYY-MM-DDTHH:MM:SS.sssZ. Default is current time.')
        mode_parser.add_argument('--use_identity', type=parse_identity,
                help='Pass a full STIX 2.1 identity object (properly escaped). Validated by the STIX2 library. Default is SIEM Rules identity.')
        mode_parser.add_argument("--ai_provider", required=False, type=parse_model, help="(required): defines the `provider:model` to be used. Select one option.", metavar="provider[:model]")
        mode_parser.add_argument("--external_refs", type=parse_ref, help="pass additional `external_references` entry (or entries) to the report object created. e.g --external_ref author=dogesec link=https://dkjjadhdaj.net", default=[], metavar="{source_name}={external_id}", action="extend", nargs='+')
        mode_parser.add_argument("--reference_urls", help="pass additional `external_references` url entry (or entries) to the report object created.", default=[], metavar="{url}", action="extend", nargs='+')
        mode_parser.add_argument("--license", help="Valid SPDX license for the rule", default=None, metavar="[LICENSE]", choices=valid_licenses())

    file.add_argument('--input_file', help='The file to be converted. Must be .txt', type=lambda x: Path(x).read_text())
    text.add_argument('--input_text', help='The text to be converted')
    sigma.add_argument('--sigma_file', help='The sigma file to be converted. Must be .yml', type=lambda x: Path(x).read_text())
    sigma.add_argument('--status', help="If passed, will overwrite any existing `status` recorded in the rule", choices=STATUSES)
    sigma.add_argument('--level', help="If passed, will overwrite any existing `level` recorded in the rule", choices=Level._member_names_)

    args: Args = parser.parse_args()
    print(args)

    if args.mode != 'sigma':
        assert args.ai_provider, "--ai_provider is required in file or txt mode"
    if args.mode == 'file':
        args.input_text = args.input_file

    args.input_text = getattr(args, 'input_text', "")
    if not args.report_id:
        args.report_id = Bundler.generate_report_id(args.use_identity.id if args.use_identity else None, args.created, args.name)

    return args


def run_txt2detection(name, identity, tlp_level, input_text: str, labels: list[str], report_id: str|uuid.UUID, ai_provider: BaseAIExtractor, **kwargs) -> Bundler:
    if sigma := kwargs.get('sigma_file'):
        detection = get_sigma_detections(sigma)
        if not identity and detection.author:
            identity = make_identity(detection.author)
        kwargs.update(reference_urls=kwargs.setdefault('reference_urls', [])+detection.references)
        if not kwargs.get('created'):
            #only consider rule.date and rule.modified if user does not pass --created
            kwargs.update(
                created=detection.date,
                modified=detection.modified,
            )
        detection.level = kwargs.get('level', detection.level)
        detection.status = kwargs.get('status', detection.status)
        detection.date = as_date(kwargs.get('created'))
        detection.modified = as_date(kwargs.get('modified'))
        detection.references = kwargs['reference_urls']
        detection.detection_id = str(report_id).removeprefix('report--')
        bundler = Bundler(name or detection.title, identity, tlp_level or detection.tlp_level or 'clear', detection.description, (labels or [])+detection.tags, report_id=report_id, **kwargs)
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
    logging.info(f"starting argument: {json.dumps(sys.argv[1:])}")
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
