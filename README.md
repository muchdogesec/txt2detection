# txt2detection

## Overview

A command line tool that takes a txt file containing threat intelligence and turns it into a detection rule.

## The problem

To illustrate the problem, lets walk through the current status quo process a human goes through when going from idea (threat TTP) to detection rule:

1. read and understand threat, maybe from a blog, report or open-source detection content
  * problem: reports on the same threat can come from multiple sources making it hard to manually collate all relevant intel
2. understand what logs or security data can be used to detect this threat, for example CloudTrail logs in this case, then understand all the field names, field values, how they are structured, how your logging pipeline structures them, etc.
  * problem: TTPs often span many logs making it hard to ensure your detection rule has full coverage
3.  convert the logic in step 1 into a detection rule (SQL/SPL/KQL, whatever) to search logs identified at step 2
  * problem: it can be hard to convert what has been read into a logical detection rule (in a detection language you may not be familiar with)
4. modify the detection rule based on new intelligence as it is discovered
  * problem: this is usually overlooked as people create and forget about rules in their detection tools

## The solution

Use the AI knowledge of threat intelligence, logs, and detection rules to create and keep them updated.

txt2detection allows a user to enter some threat intelligence as a file to considered be turned into a detection.

1. User uploads files (Selects products in their stack)
2. Based on user inputs, AI prompts structured and sent
3. Rules converted into STIX objects

## Usage

### Setup

Install the required dependencies using:

```shell
# clone the latest code
git clone https://github.com/muchdogesec/txt2detection
cd txt2detection
# create a venv
python3 -m venv txt2detection-venv
source txt2detection-venv/bin/activate
# install requirements
pip3 install -r requirements.txt
```

Now copy the `.env` file to set your config:

```shell
cp .env.example .env
```

### Run

```shell
python3 txt2detection.py \
  --input_file FILE.txt \
  --name NAME \
  --tlp_level TLP_LEVEL \
  --labels label1,label2 \
  --created DATE \
  --use_identity \{IDENTITY JSON\} \
  --products_in_stack product1,products2 \
  --detection_language detection_language
```

* `--input_file` (required): the file to be converted. Must be `.txt`
* `--name` (required): name of file, max 72 chars. Will be used in the STIX Report Object created.
* `--tlp_level` (optional): Options are `clear`, `green`, `amber`, `amber_strict`, `red`. Default if not passed, is `clear`.
* `--labels` (optional): comma seperated list of labels. Case-insensitive (will all be converted to lower-case). Allowed `a-z`, `0-9`. e.g.`label1,label2` would create 2 labels.
* `--created` (optional): by default all object `created` times will take the time the script was run. If you want to explicitly set these times you can do so using this flag. Pass the value in the format `YYYY-MM-DDTHH:MM:SS.sssZ` e.g. `2020-01-01T00:00:00.000Z`
* `--use_identity` (optional): can pass a full STIX 2.1 identity object (make sure to properly escape). Will be validated by the STIX2 library. If none passed, the default SIEM Rules identity will be used.
* `--products_in_stack_keys` (required): the products listed provide the AI with the context of how to write the detecion rules to search the correct log source. You can find a list of all products in `config/logs.yaml` under each records `product` value (e.g. `amazon_web_services,google_cloud_platform`)
* `--detection_language_key` (required): the detection rule language you want the output to be in. You can find a list of detection language keys in `config/detection_languages.yaml`

## Adding new logs / detection languages

### To add a new log

First, add some samples of the log in `log_samples`. These will be passed to the AI to help it understand its structure. The more samples you can provide, the more accurate the detections will be for it.

Then create a record for the log type in `config/logs.yaml`.

### To add a new detection language

Adding a new detection language is fairly trivial. However, there is a implicit understanding the model understands the detection rule structure. Results can therefore be mixed, so it is worth testing in detail.

All you need to do is add a new record in `config/detection_languages.yaml`.

## AI Prompts

### Prompt structure

```txt
<context>
You are a threat intelligence analyst tasked with converting cyber security threat intelligence into detection rule.

Your threat intelligence will be provided in the form of threat intelligence reports that describes the indicators of compromise, techniques, tactics or procedures of an adversary. This threat intelligence will be provided to you in the `<context>` tags as your input.

You need to comprehensively understand the threat intelligence provided, identifying indicators of compromise and behaviours.

The following log sources are what must be searched to identify the indicators of compromise and behaviours you identify:

* <list of log sources for products used> (sample log: <sample url on github>)

Using the the indicators of compromise and behaviours you identify and the structure of the logs needed to be searched, create a <detection rule name> in markdown format. If you need help refer to the <detection rule name> documentation here <docs url>.

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

The output should be a JSON file with this information as follows:

{
  "rules": [
    {
      "name": "NAME",
      "description": "DESCRIPTION",
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

</context>

<requirement>
Think about your answer first before you respond.

Print only the JSON content in the response.

If you don't know the answer, just say that you don't know, don't try to make up an answer.
</requirement>

<style>
The response should be written in a clear, concise, and technical style, suitable for cybersecurity professionals. Use terminology and structures familiar to cybersecurity threat analysis and detection development.
</style>

<tone>
The tone should be objective and analytical, focusing on providing clear and factual information without unnecessary embellishments or subjective interpretations.
</tone>

<audience>
The intended audience is cybersecurity analysts and engineers who are responsible for creating new detections. They have a deep understanding of cybersecurity concepts, threat intelligence, and detection mechanisms.
</audience>
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
    "id": "report--<UUID V4 GENERATED BY STIX2 LIBRARY>",
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
    "id": "indicator--<UUIDV5>",
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

## Support

[Minimal support provided via the DOGESEC community](https://community.dogesec.com/).

## License

[Apache 2.0](/LICENSE).