import typing

if typing.TYPE_CHECKING:
    from .bundler import Bundler


def map_technique_tactic(obj, report_tactics, rule_tactics):
    """
    Return first matching tactics in the same rule
    If no tactic match, try to return from all the tactics in report
    If none exist, return nothing
    """
    technique_name = obj["external_references"][0]["external_id"]
    tactic_name = None
    tactic_names = set()
    for phase in obj["kill_chain_phases"]:
        if not set(phase["kill_chain_name"].split("-")).issuperset(["mitre", "attack"]):
            continue
        tactic_names.add(phase["phase_name"])
    tactic_obj = None
    if s := tactic_names.intersection(rule_tactics):
        tactic_obj = rule_tactics[s.pop()]
    elif tactic_names.intersection(report_tactics):
        tactic_obj = report_tactics[s.pop()]
    if tactic_obj:
        tactic_name = tactic_obj["external_references"][0]["external_id"]
    return technique_name, tactic_name


def create_navigator_layer(report, indicator, technique_mapping, mitre_version):
    techniques = []
    for technique_id, tactic in technique_mapping.items():
        technique_item = dict(
            techniqueID=technique_id,
            score=100,
            showSubtechniques=True,
        )
        if tactic:
            technique_item["tactic"] = tactic
        techniques.append(technique_item)

    return {
        "name": indicator["name"],
        "domain": "enterprise-attack",
        "description": indicator["description"],
        "versions": {
            "layer": "4.5",
            "attack": mitre_version,
            "navigator": "5.1.0",
        },
        "techniques": techniques,
        "gradient": {
            "colors": ["#ffffff", "#ff6666"],
            "minValue": 0,
            "maxValue": 100,
        },
        "legendItems": [],
        "metadata": [
            {"name": "report_id", "value": report.id, "rule_id": indicator["id"]}
        ],
        "links": [
            {
                "label": "Generated using txt2detection",
                "url": "https://github.com/muchdogesec/txt2detection/",
            }
        ],
        "layout": {"layout": "side"},
    }
