import contextlib
import enum
import json
import logging
import os
from urllib.parse import urljoin
import requests
from stix2 import (
    Report,
    Identity,
    MarkingDefinition,
    Relationship,
    Bundle,
)
from stix2.serialization import serialize
import hashlib

from txt2detection.ai_extractor.utils import Detection, DetectionContainer, UUID_NAMESPACE

from datetime import UTC, datetime as dt
import uuid
from stix2 import parse as parse_stix



logger = logging.getLogger("txt2detection.bundler")


class TLP_LEVEL(enum.Enum):
    CLEAR = MarkingDefinition(
        spec_version="2.1",
        id="marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
        created="2022-10-01T00:00:00.000Z",
        definition_type="TLP:CLEAR",
        extensions={
            "extension-definition--60a3c5c5-0d10-413e-aab3-9e08dde9e88d": {
                "extension_type": "property-extension",
                "tlp_2_0": "clear",
            }
        },
    )
    GREEN = MarkingDefinition(
        spec_version="2.1",
        id="marking-definition--bab4a63c-aed9-4cf5-a766-dfca5abac2bb",
        created="2022-10-01T00:00:00.000Z",
        definition_type="TLP:GREEN",
        extensions={
            "extension-definition--60a3c5c5-0d10-413e-aab3-9e08dde9e88d": {
                "extension_type": "property-extension",
                "tlp_2_0": "green",
            }
        },
    )
    AMBER = MarkingDefinition(
        spec_version="2.1",
        id="marking-definition--55d920b0-5e8b-4f79-9ee9-91f868d9b421",
        created="2022-10-01T00:00:00.000Z",
        definition_type="TLP:AMBER",
        extensions={
            "extension-definition--60a3c5c5-0d10-413e-aab3-9e08dde9e88d": {
                "extension_type": "property-extension",
                "tlp_2_0": "amber",
            }
        },
    )
    AMBER_STRICT = MarkingDefinition(
        spec_version="2.1",
        id="marking-definition--939a9414-2ddd-4d32-a0cd-375ea402b003",
        created="2022-10-01T00:00:00.000Z",
        definition_type="TLP:AMBER+STRICT",
        extensions={
            "extension-definition--60a3c5c5-0d10-413e-aab3-9e08dde9e88d": {
                "extension_type": "property-extension",
                "tlp_2_0": "amber+strict",
            }
        },
    )
    RED = MarkingDefinition(
        spec_version="2.1",
        id="marking-definition--e828b379-4e03-4974-9ac4-e53a884c97c1",
        created="2022-10-01T00:00:00.000Z",
        definition_type="TLP:RED",
        extensions={
            "extension-definition--60a3c5c5-0d10-413e-aab3-9e08dde9e88d": {
                "extension_type": "property-extension",
                "tlp_2_0": "red",
            }
        },
    )

    @classmethod
    def levels(cls):
        return dict(
            clear=cls.CLEAR,
            green=cls.GREEN,
            amber=cls.AMBER,
            amber_strict=cls.AMBER_STRICT,
            red=cls.RED,
        )

    @classmethod
    def values(cls):
        return [
            cls.CLEAR.value,
            cls.GREEN.value,
            cls.AMBER.value,
            cls.AMBER_STRICT.value,
            cls.RED.value,
        ]

    @classmethod
    def get(cls, level):
        if isinstance(level, cls):
            return level
        if level not in cls.levels():
            raise Exception(f'unsupported tlp level: `{level}`')
        return cls.levels()[level]

    @property
    def name(self):
        return super().name.lower()


class Bundler:
    identity = None
    object_marking_refs = []
    uuid = None
    id_map = dict()
    detections: DetectionContainer
    # https://raw.githubusercontent.com/muchdogesec/stix4doge/refs/heads/main/objects/identity/txt2detection.json
    default_identity = Identity(**{
        "type": "identity",
        "spec_version": "2.1",
        "id": "identity--a4d70b75-6f4a-5d19-9137-da863edd33d7",
        "created_by_ref": "identity--9779a2db-f98c-5f4b-8d08-8ee04e02dbb5",
        "created": "2020-01-01T00:00:00.000Z",
        "modified": "2020-01-01T00:00:00.000Z",
        "name": "txt2detection",
        "description": "https://github.com/muchdogesec/txt2detection",
        "identity_class": "system",
        "sectors": [
            "technology"
        ],
        "contact_information": "https://www.dogesec.com/contact/",
        "object_marking_refs": [
            "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
            "marking-definition--97ba4e8b-04f6-57e8-8f6e-3a0f0a7dc0fb"
        ]
    })
    # https://raw.githubusercontent.com/muchdogesec/stix4doge/refs/heads/main/objects/marking-definition/txt2detection.json
    default_marking = MarkingDefinition(**{
        "type": "marking-definition",
        "spec_version": "2.1",
        "id": "marking-definition--a4d70b75-6f4a-5d19-9137-da863edd33d7",
        "created_by_ref": "identity--9779a2db-f98c-5f4b-8d08-8ee04e02dbb5",
        "created": "2020-01-01T00:00:00.000Z",
        "definition_type": "statement",
        "definition": {
            "statement": "This object was created using: https://github.com/muchdogesec/txt2detection"
        },
        "object_marking_refs": [
            "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
            "marking-definition--97ba4e8b-04f6-57e8-8f6e-3a0f0a7dc0fb"
        ]
    })

    @classmethod
    def generate_report_id(cls, created_by_ref, created, name):
        if not created_by_ref:
            created_by_ref = cls.default_identity['id']
        return str(
            uuid.uuid5(UUID_NAMESPACE, f"{created_by_ref}+{created}+{name}")
        )

    def __init__(
        self,
        name,
        identity,
        tlp_level,
        description,
        confidence,
        labels,
        created=None,
        modified=None,
        report_id=None,
        external_refs: list=None,
        reference_urls=None,
        license=None,
        status='experimental',
        **kwargs,
    ) -> None:
        self.created = created or dt.now(UTC)
        self.modified = modified or self.created
        self.identity = identity or self.default_identity
        self.tlp_level = TLP_LEVEL.get(tlp_level)
        self.uuid = report_id or self.generate_report_id(self.identity.id, self.created, name)
        self.reference_urls = reference_urls or []
        self.labels = labels or []
        self.license = license
        self.indicator_status = status

        self.job_id = f"report--{self.uuid}"
        self.url_refs = [dict(source_name='txt2detection', url=url, description='txt2detection-reference') for url in self.reference_urls]
        self.report = Report(
            created_by_ref=self.identity.id,
            name=name,
            id=self.job_id,
            description=description,
            object_refs=[
                f"note--{self.uuid}"
            ],  # won't allow creation with empty object_refs
            created=self.created,
            modified=self.modified,
            object_marking_refs=[self.tlp_level.value.id],
            labels=self.labels,
            published=self.created,
            external_references=[
                {
                    "source_name": "description_md5_hash",
                    "external_id": hashlib.md5(description.encode()).hexdigest(),
                },
            ] + (external_refs or []) + self.url_refs,
            confidence=confidence,
        )
        self.report.object_refs.clear()  # clear object refs
        self.set_defaults()

    def set_defaults(self):
        # self.value.extend(TLP_LEVEL.values()) # adds all tlp levels
        self.bundle = Bundle(objects=[self.tlp_level.value], id=f"bundle--{self.uuid}")

        self.bundle.objects.extend([self.default_marking, self.identity, self.report])
        # add default STIX 2.1 marking definition for txt2detection
        self.report.object_marking_refs.append(self.default_marking.id)


    def add_ref(self, sdo):
        sdo_id = sdo["id"]
        if sdo_id not in self.report.object_refs:
            self.report.object_refs.append(sdo_id)
            self.bundle.objects.append(sdo)

    def add_rule_indicator(self, detection: Detection):
        indicator = {
            "type": "indicator",
            "id": "indicator--"+detection.id,
            "spec_version": "2.1",
            "created_by_ref": self.report.created_by_ref,
            "created": self.report.created,
            "modified": self.report.modified,
            "indicator_types": detection.indicator_types,
            "name": detection.title,
            "labels": self.labels,
            "pattern_type": 'sigma',
            "pattern": detection.make_rule(self),
            "valid_from": self.report.created,
            "object_marking_refs": self.report.object_marking_refs,
            "external_references": self.url_refs + [dict(source_name="txt2detection-status", external_id=self.indicator_status)],
            "confidence": detection.confidence,
        }
        logger.debug(f"===== rule {detection.id} =====")
        logger.debug("```yaml\n"+indicator['pattern']+"\n```")
        logger.debug(f" =================== end of rule =================== ")

        for obj in self.get_attack_objects(detection.mitre_attack_ids):
            self.add_ref(obj)
            self.add_relation(indicator, obj, 'mitre-attack')

        for obj in self.get_cve_objects(detection.cve_ids):
            self.add_ref(obj)
            self.add_relation(indicator, obj, 'nvd-cve')
            
        self.add_ref(parse_stix(indicator, allow_custom=True))

    def add_relation(self, indicator, target_object, type='mitre-attack'):
        ext_refs = []

        with contextlib.suppress(Exception):
            indicator['external_references'].append(target_object['external_references'][0])
            ext_refs = [target_object['external_references'][0]]

        rel =  Relationship(
            id="relationship--" + str(
                uuid.uuid5(
                    UUID_NAMESPACE, f"{type}+{indicator['id']}+{target_object['id']}"
                )
            ),
            source_ref=indicator['id'],
            target_ref=target_object['id'],
            relationship_type=type,
            created_by_ref=self.report.created_by_ref,
            description=f"{indicator['name']} is linked to  {target_object['external_references'][0]['external_id']} ({target_object['name']})",
            created=self.report.created,
            modified=self.report.modified,
            object_marking_refs=self.report.object_marking_refs,
            external_references=ext_refs,
            allow_custom=True,
        )
        self.add_ref(rel)

    def to_json(self):
        return serialize(self.bundle, indent=4)
    
    @property
    def bundle_dict(self):
        return json.loads(self.to_json())
    
    def get_attack_objects(self, attack_ids):
        if not attack_ids:
            return []
        logger.debug(f"retrieving attack objects: {attack_ids}")
        endpoint = urljoin(os.environ['CTIBUTLER_BASE_URL'] + '/', f"v1/attack-enterprise/objects/?attack_id="+','.join(attack_ids))

        headers = {}
        if api_key := os.environ.get('CTIBUTLER_API_KEY'):
            headers['API-KEY'] = api_key

        return self._get_objects(endpoint, headers)
    
        
    def get_cve_objects(self, cve_ids):
        if not cve_ids:
            return []
        logger.debug(f"retrieving cve objects: {cve_ids}")
        endpoint = urljoin(os.environ['VULMATCH_BASE_URL'] + '/', f"v1/cve/objects/?cve_id="+','.join(cve_ids))
        headers = {}
        if api_key := os.environ.get('VULMATCH_API_KEY'):
            headers['API-KEY'] = api_key

        return self._get_objects(endpoint, headers)
    
    
    def _get_objects(self, endpoint, headers):
        data = []
        page = 1
        while True:
            resp = requests.get(endpoint, params=dict(page=page, page_size=1000), headers=headers)
            if resp.status_code != 200:
                break
            d = resp.json()
            if len(d['objects']) == 0:
                break
            data.extend(d['objects'])
            page+=1
            if d['page_results_count'] < d['page_size']:
                break
        return data
    
    def bundle_detections(self, container: DetectionContainer):
        self.detections = container
        if not container.success:
            return
        for d in container.detections:
            self.add_rule_indicator(d)