import contextlib
import enum
import itertools
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

from txt2detection import attack_navigator, observables
from txt2detection.models import (
    AIDetection,
    BaseDetection,
    DataContainer,
    DetectionContainer,
    UUID_NAMESPACE,
    SigmaRuleDetection,
)

from datetime import UTC, datetime as dt
import uuid
from stix2 import parse as parse_stix

from txt2detection.models import TLP_LEVEL
from txt2detection.utils import (
    STATUSES,
    load_stix_object_from_url,
    remove_rule_specific_tags,
)


logger = logging.getLogger("txt2detection.bundler")


class Bundler:
    identity = None
    object_marking_refs = []
    uuid = None
    id_map = dict()
    data: DataContainer
    # https://raw.githubusercontent.com/muchdogesec/stix4doge/refs/heads/main/objects/identity/txt2detection.json
    default_identity = Identity(
        **{
            "type": "identity",
            "spec_version": "2.1",
            "id": "identity--a4d70b75-6f4a-5d19-9137-da863edd33d7",
            "created_by_ref": "identity--9779a2db-f98c-5f4b-8d08-8ee04e02dbb5",
            "created": "2020-01-01T00:00:00.000Z",
            "modified": "2020-01-01T00:00:00.000Z",
            "name": "txt2detection",
            "description": "https://github.com/muchdogesec/txt2detection",
            "identity_class": "system",
            "sectors": ["technology"],
            "contact_information": "https://www.dogesec.com/contact/",
            "object_marking_refs": [
                "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
                "marking-definition--97ba4e8b-04f6-57e8-8f6e-3a0f0a7dc0fb",
            ],
        }
    )
    # https://raw.githubusercontent.com/muchdogesec/stix4doge/refs/heads/main/objects/marking-definition/txt2detection.json
    default_marking = MarkingDefinition(
        **{
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
                "marking-definition--97ba4e8b-04f6-57e8-8f6e-3a0f0a7dc0fb",
            ],
        }
    )

    sigma_extension_definition = load_stix_object_from_url(
        "https://github.com/muchdogesec/stix2extensions/raw/refs/heads/main/automodel_generated/extension-definitions/properties/indicator-sigma-rule.json"
    )
    data_source_extension_definition = load_stix_object_from_url(
        "https://raw.githubusercontent.com/muchdogesec/stix2extensions/refs/heads/main/automodel_generated/extension-definitions/scos/data-source.json"
    )

    @classmethod
    def generate_report_id(cls, created_by_ref, created, name):
        if not created_by_ref:
            created_by_ref = cls.default_identity["id"]
        return str(uuid.uuid5(UUID_NAMESPACE, f"{created_by_ref}+{created}+{name}"))

    def __init__(
        self,
        name,
        identity,
        tlp_level,
        description,
        labels,
        created=None,
        modified=None,
        report_id=None,
        external_refs: list = None,
        reference_urls=None,
        license=None,
        **kwargs,
    ) -> None:
        self.created = created or dt.now(UTC)
        self.modified = modified or self.created
        self.identity = identity or self.default_identity
        self.tlp_level = TLP_LEVEL.get(tlp_level or "clear")
        self.uuid = report_id or self.generate_report_id(
            self.identity.id, self.created, name
        )
        self.reference_urls = reference_urls or []
        self.labels = labels or []
        self.license = license

        self.all_objects = set()
        self.job_id = f"report--{self.uuid}"
        self.external_refs = (external_refs or []) + [
            dict(
                source_name="txt2detection",
                url=url,
                description="txt2detection-reference",
            )
            for url in self.reference_urls
        ]
        self.data = DataContainer.model_construct()
        self.tactics = {}
        self.techniques = {}

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
            labels=remove_rule_specific_tags(self.labels),
            published=self.created,
            external_references=[
                dict(
                    source_name="description_md5_hash",
                    external_id=hashlib.md5((description or "").encode()).hexdigest(),
                )
            ]
            + self.external_refs,
        )
        self.report.object_refs.clear()  # clear object refs
        self.set_defaults()
        if not description:
            self.report.external_references.pop(0)

    def set_defaults(self):
        # self.value.extend(TLP_LEVEL.values()) # adds all tlp levels
        self.bundle = Bundle(objects=[self.tlp_level.value], id=f"bundle--{self.uuid}")

        self.bundle.objects.extend([self.default_marking, self.identity, self.report])
        # add default STIX 2.1 marking definition for txt2detection
        self.report.object_marking_refs.append(self.default_marking.id)
        self.add_ref(self.sigma_extension_definition)
        self.add_ref(self.data_source_extension_definition)

    def add_ref(self, sdo, append_report=False):
        sdo_id = sdo["id"]
        if sdo_id in self.all_objects:
            return
        self.bundle.objects.append(sdo)
        if sdo_id not in self.report.object_refs and append_report:
            self.report.object_refs.append(sdo_id)
        self.all_objects.add(sdo_id)

    def add_rule_indicator(self, detection: SigmaRuleDetection):
        indicator_types = getattr(detection, "indicator_types", None)
        if isinstance(detection, AIDetection):
            detection = detection.to_sigma_rule_detection(self)
        assert isinstance(
            detection, SigmaRuleDetection
        ), f"detection of type {type(detection)} not supported"
        indicator = {
            "type": "indicator",
            "id": "indicator--" + str(detection.detection_id),
            "spec_version": "2.1",
            "created_by_ref": self.report.created_by_ref,
            "created": self.report.created,
            "modified": self.report.modified,
            "indicator_types": indicator_types,
            "name": detection.title,
            "description": detection.description,
            "labels": remove_rule_specific_tags(self.labels),
            "pattern_type": "sigma",
            "pattern": detection.make_rule(self),
            "valid_from": self.report.created,
            "object_marking_refs": self.report.object_marking_refs,
            "external_references": self.external_refs,
            "extensions": {
                self.sigma_extension_definition["id"]: {
                    "extension_type": "toplevel-property-extension"
                }
            },
            "x_sigma_type": "base",
            "x_sigma_level": detection.level,
            "x_sigma_status": detection.status,
            "x_sigma_license": detection.license,
            "x_sigma_fields": detection.fields,
            "x_sigma_falsepositives": detection.falsepositives,
            "x_sigma_scope": detection.scope,
        }
        indicator["external_references"].append(
            {
                "source_name": "rule_md5_hash",
                "external_id": hashlib.md5(indicator["pattern"].encode()).hexdigest(),
            }
        )
        logsource = detection.make_data_source()

        logger.debug(f"===== rule {detection.detection_id} =====")
        logger.debug("```yaml\n" + indicator["pattern"] + "\n```")
        logger.debug(f" =================== end of rule =================== ")

        self.data.attacks.update(dict.fromkeys(detection.mitre_attack_ids, "Not found"))
        tactics = self.tactics[detection.id] = {}
        techniques = self.techniques[detection.id] = []
        for obj in self.get_attack_objects(detection.mitre_attack_ids):
            self.add_ref(obj)
            self.add_relation(indicator, obj)
            self.data.attacks[obj["external_references"][0]["external_id"]] = obj["id"]
            if obj["type"] == "x-mitre-tactic":
                tactics[obj["x_mitre_shortname"]] = obj
            else:
                techniques.append(obj)

        self.data.cves.update(dict.fromkeys(detection.cve_ids, "Not found"))
        for obj in self.get_cve_objects(detection.cve_ids):
            self.add_ref(obj)
            self.add_relation(indicator, obj)
            self.data.cves[obj["name"]] = obj["id"]

        self.add_ref(parse_stix(indicator, allow_custom=True), append_report=True)
        self.add_ref(logsource, append_report=True)
        self.add_relation(
            indicator,
            logsource,
            description=f'{indicator["name"]} is created from {make_logsouce_string(logsource)}',
        )

        self.data.observables = []
        for ob_type, ob_value in set(
            observables.find_stix_observables(detection.detection)
        ):
            self.data.observables.append(dict(type=ob_type, value=ob_value))
            try:
                obj = observables.to_stix_object(ob_type, ob_value)
                self.add_ref(obj)
                self.add_relation(indicator, obj, "related-to", target_name=ob_value)
            except Exception as e:
                self.data.observables[-1]["error"] = str(e)
                logger.exception(f"failed to process observable {ob_type}/{ob_value}")

    def add_relation(
        self,
        indicator,
        target_object,
        relationship_type="related-to",
        target_name=None,
        description=None,
    ):
        ext_refs = []

        with contextlib.suppress(Exception):
            indicator["external_references"].append(
                target_object["external_references"][0]
            )
            ext_refs = [target_object["external_references"][0]]

        if not description:
            target_name = (
                target_name
                or f"{target_object['external_references'][0]['external_id']} ({target_object['name']})"
            )
            description = f"{indicator['name']} {relationship_type} {target_name}"

        rel = Relationship(
            id="relationship--"
            + str(
                uuid.uuid5(UUID_NAMESPACE, f"{indicator['id']}+{target_object['id']}")
            ),
            source_ref=indicator["id"],
            target_ref=target_object["id"],
            relationship_type=relationship_type,
            created_by_ref=self.report.created_by_ref,
            description=description,
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
        endpoint = urljoin(
            os.environ["CTIBUTLER_BASE_URL"] + "/",
            f"v1/attack-enterprise/objects/?attack_id=" + ",".join(attack_ids),
        )

        headers = {}
        if api_key := os.environ.get("CTIBUTLER_API_KEY"):
            headers["API-KEY"] = api_key

        return self._get_objects(endpoint, headers)

    @classmethod
    def get_attack_version(cls):
        headers = {}
        api_root = os.environ["CTIBUTLER_BASE_URL"] + "/"
        if api_key := os.environ.get("CTIBUTLER_API_KEY"):
            headers["API-KEY"] = api_key
        version_url = urljoin(api_root, f"v1/attack-enterprise/versions/installed/")
        return requests.get(version_url, headers=headers).json()["latest"]

    @classmethod
    def get_cve_objects(cls, cve_ids):
        if not cve_ids:
            return []
        logger.debug(f"retrieving cve objects: {cve_ids}")
        endpoint = urljoin(
            os.environ["VULMATCH_BASE_URL"] + "/",
            f"v1/cve/objects/?cve_id=" + ",".join(cve_ids),
        )
        headers = {}
        if api_key := os.environ.get("VULMATCH_API_KEY"):
            headers["API-KEY"] = api_key

        return cls._get_objects(endpoint, headers)

    @classmethod
    def _get_objects(cls, endpoint, headers):
        data = []
        page = 1
        while True:
            resp = requests.get(
                endpoint, params=dict(page=page, page_size=1000), headers=headers
            )
            if resp.status_code != 200:
                break
            d = resp.json()
            if len(d["objects"]) == 0:
                break
            data.extend(d["objects"])
            page += 1
            if d["page_results_count"] < d["page_size"]:
                break
        return data

    def bundle_detections(self, container: DetectionContainer):
        self.data.detections = container
        if not container.success:
            return
        for d in container.detections:
            self.add_rule_indicator(d)

    def create_attack_navigator(self):
        self.mitre_version = self.get_attack_version()
        all_tactics = dict(
            itertools.chain(*map(lambda x: x.items(), self.tactics.values()))
        )
        self.data.navigator_layer = {}
        for detection_id, techniques in self.techniques.items():
            if not techniques:
                continue
            tactics = self.tactics[detection_id]
            mapping = dict(
                [
                    attack_navigator.map_technique_tactic(
                        technique, all_tactics, tactics
                    )
                    for technique in techniques
                ]
            )
            indicator = [
                f
                for f in self.bundle.objects
                if str(f["id"]).endswith(str(detection_id)) and f["type"] == "indicator"
            ][0]
            self.data.navigator_layer[detection_id] = (
                attack_navigator.create_navigator_layer(
                    self.report, indicator, mapping, self.mitre_version
                )
            )


def make_logsouce_string(source: dict):
    d = [
        f"{k}={v}" for k, v in source.items() if k in ["product", "service", "category"]
    ]
    d_str = ", ".join(d)
    return "log-source {" + d_str + "}"
