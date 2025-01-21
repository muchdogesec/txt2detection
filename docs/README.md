## AI Prompts

### Prompt structure

```txt
<context>
You are a threat intelligence analyst tasked with converting cyber security threat intelligence into detection rules that can identify the behaviour described in the intelligence.

Your threat intelligence will be provided in the form of threat reports that describes the indicators of compromise, techniques, tactics or procedures of an adversary. This threat intelligence will be provided to you in the `<context>` tags as your input.

You need to comprehensively understand the threat intelligence provided, identifying the indicators of compromise, techniques, tactics or procedures of an adversary.

Using this understanding you should best determine the log sources that can be searched to identify what is being described. It is possible that the search spans multiple log sources, but at least one log source must be defined.

By combining intelligence and log sources identified, create a <detection rule name> in markdown format. If you need help refer to the <detection rule name> documentation here <docs url>.

It is possible that you create zero or more detection rules.

You need to document each detection rule clearly, outlining its purpose (as its name) and the logic and the specific TTP it addresses (as its description). You should also classify each rule with one or more indicator_types from the following list; 

* anomalous-activity
* anonymization
* benign
* compromised
* malicious-activity
* attribution
* unknown

Also, when relevant, you should add a list of MITRE ATT&CK Tactics, Techniques, or Sub-Techniques detected by this rule. You should print the ATT&CK IDs in the property `mitre_attack_ids`.
</context>

<requirement>

The output should be a JSON file with this information as follows:

{
    "rules": [
        {
            "name": "NAME",
            "description": "DESCRIPTION",
            "log_sources": [
                "LOG SOURCE N"
            ]
            "rule": "RULE",
            "indicator_types": [
                "TYPES"
            ],
            "mitre_attack_ids": [
                "TYPES"
            ]
        },
        {
            "name": "NAME",
            "description": "DESCRIPTION",
            "log_sources": [
                "LOG SOURCE N"
            ]
            "rule": "RULE",
            "indicator_types": [
                "TYPES"
            ],
            "mitre_attack_ids": [
                "TYPES"
            ]
        }
    ]
}

Think about your answer first before you respond.

Print only the JSON content in the response.

If you don't know the answer, just say that you don't know, don't try to make up an answer.
</requirement>
```

## STIX conversion

The inputs and outputs are all coded into STIX 2.1 objects as follows...

### Default STIX objects

#### TLPs

```python
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
```

Only the tlp set is imported to final bundle.

#### SIEM Rules Identity

https://raw.githubusercontent.com/muchdogesec/stix4doge/refs/heads/main/objects/identity/siemrules.json

Only imported if user does not specify their own identity

#### SIEM Rules Marking Definition

https://raw.githubusercontent.com/muchdogesec/stix4doge/refs/heads/main/objects/marking-definition/siemrules.json

Always imported to bundle

### Report SDO (`report`)

All files uploaded are represented as a unique [STIX Report SDO](https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_n8bjzg1ysgdq) that take the following structure;

```json
{
    "type": "report",
    "spec_version": "2.1",
    "id": "report--<UUID V4 GENERATED BY STIX2 LIBRARY OR USER ENTERED AT INPUT>",
    "created_by_ref": "identity--<IDENTITY OBJECT USED AT UPLOAD>",
    "created": "<ITEM INGEST DATE OR DATE SET AT UPLOAD>",
    "modified": "<ITEM INGEST DATE OR DATE SET AT UPLOAD>",
    "name": "<NAME ENTERED ON UPLOAD>",
    "description": "<FULL BODY OF TEXT FILE>",
    "published": "<ITEM INGEST DATE OR DATE SET AT UPLOAD>",
    "object_marking_refs": [
        "marking-definition--<TLP LEVEL SET AT UPLOAD>",
        "marking-definition--8ef05850-cb0d-51f7-80be-50e4376dbe63"
    ],
    "labels": [
        "<LABELS ADDED BY USER>"
    ],
    "external_references": [
        {
            "description": "description_md5_hash",
            "external_id": "<MD5 HASH OF DESCRIPTION FIELD>"
        }   
    ],
    "object_refs": [
        "<LIST OF ALL OBJECTS CREATED>"
    ]
}
```

### Indicator SDO (`indicator`)

For each detection rule produced by the AI (there could be more than one) an Indicator object is created as follows;

```json
{
    "type": "indicator",
    "spec_version": "2.1",
    "id": "indicator--<UUIDV4>",
    "created_by_ref": "<SAME AS REPORT OBJECT IDENTITY VALUE>",
    "created": "<SAME AS REPORT OBJECT CREATED VALUE>",
    "modified": "<SAME AS REPORT OBJECT MODIFIED VALUE>",
    "indicator_types": [
        "<AI TYPES>"
    ],
    "name": "<AI NAME>",
    "pattern_type": "<detection_rule_lang>",
    "pattern": "<DETECTION_RULE>",
    "valid_from": "<REPORT CREATED PROPERTY VALUE>",
    "object_marking_refs": [
        "marking-definition--<TLP LEVEL SET>",
        "marking-definition--8ef05850-cb0d-51f7-80be-50e4376dbe63"
    ]
}
```

### MITRE ATT&CK lookup 

Where MITRE ATT&CK Enterprise tactics/techniques detected, they are added to the bundle and joined to the Indicator object containing the detection;

```json
{
    "type": "relationship",
    "spec_version": "2.1",
    "id": "relationship--<GENERATED BY STIX2 LIBRARY>",
    "created_by_ref": "<SAME AS REPORT OBJECT IDENTITY VALUE>",
    "created": "<SAME AS REPORT OBJECT CREATED VALUE>",
    "modified": "<SAME AS REPORT MODIFIED CREATED VALUE>",
    "relationship_type": "mitre-attack",
    "description": "<INDICATOR NAME> is linked to <ATT&CK NAME>",
    "source_ref": "indicator--<ID>",
    "target_ref": "<MITRE ATT&CK OBJECT>",
    "object_marking_refs": [
        "marking-definition--<TLP LEVEL SET>"
        "marking-definition--8ef05850-cb0d-51f7-80be-50e4376dbe63"
    ]
}
```

The objects themselves are imported from [CTI Butler](https://github.com/muchdogesec/ctibutler) defined in the `.env` file.

## Bundle (script output)

The output of txt2stix is a STIX bundle file.

This bundle takes the format;

```json
{
    "type": "bundle",
    "id": "bundle--<SAME AS REPORT UUID PART>",
    "objects": [
        "<ALL STIX JSON DEFAULT AND EXTRACTED OBJECTS>"
    ]
}
```

The objects include all SROs generated for the input.

The output filename of the bundle takes the format: `bundle--<ID>.json`
