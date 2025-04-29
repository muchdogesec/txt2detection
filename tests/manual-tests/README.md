# AI Rule Gen Tests

## Check TLP

```shell
python3 txt2detection.py file \
  --input_file tests/files/CVE-2024-56520.txt \
  --name "Check TLP" \
  --ai_provider openai:gpt-4o \
  --tlp_level red \
  --report_id e91a49ba-f935-4844-8b37-0d5e963f0683
```

## Check labels

Should fail because no namespace

```shell
python3 txt2detection.py file \
  --input_file tests/files/CVE-2024-56520.txt \
  --name "Check bad labels" \
  --ai_provider openai:gpt-4o \
  --labels "label1","label_2" \
  --report_id 139d8b41-c5c8-48fa-aa25-39a54dfa1227
```

Should pass

```shell
python3 txt2detection.py file \
  --input_file tests/files/CVE-2024-56520.txt \
  --name "Check labels" \
  --ai_provider openai:gpt-4o \
  --labels "namespace.label1" "namespace.label_2" \
  --report_id a3731edf-e834-43d2-95b8-e03f37bde9ba
```

## Check special labels

Should fail because disallowed tag

```shell
python3 txt2detection.py file \
  --input_file tests/files/CVE-2024-56520.txt \
  --name "Disallowed tag" \
  --ai_provider openai:gpt-4o \
  --labels "tlp.red" \
  --report_id a6f2aaff-4e33-4280-bb01-ab1bd3b95362
```

Should have cve tag and matching vulnerability object

```shell
python3 txt2detection.py file \
  --input_file tests/files/CVE-2024-56520.txt \
  --name "CVE tags" \
  --ai_provider openai:gpt-4o \
  --labels "cve.2025-3593" \
  --report_id fab3707e-00fc-4f35-9d6d-e72dc0b6ba08
```

Should have attack tags and matching attack pattern and x-mitre-tactic objects

```shell
python3 txt2detection.py file \
  --input_file tests/files/CVE-2024-56520.txt \
  --name "ATT&CK tags tag" \
  --ai_provider openai:gpt-4o \
  --labels "attack.t1071.001" "attack.command-and-control" \
  --report_id 940e8807-381e-41df-a27e-08914bafd93c
```

## Check custom identity

```shell
python3 txt2detection.py file \
  --input_file tests/files/CVE-2024-56520.txt \
  --name "Check custom identity" \
  --ai_provider openai:gpt-4o \
  --use_identity '{"type":"identity","spec_version":"2.1","id":"identity--8ef05850-cb0d-51f7-80be-50e4376dbe63","created_by_ref":"identity--9779a2db-f98c-5f4b-8d08-8ee04e02dbb5","created":"2020-01-01T00:00:00.000Z","modified":"2020-01-01T00:00:00.000Z","name":"siemrules","description":"https://github.com/muchdogesec/siemrules","identity_class":"system","sectors":["technology"],"contact_information":"https://www.dogesec.com/contact/","object_marking_refs":["marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487","marking-definition--97ba4e8b-04f6-57e8-8f6e-3a0f0a7dc0fb"]}' \
  --report_id f6f5bcb9-095f-47fb-b286-92b6a2aee221
```

## Check created by time

```shell
python3 txt2detection.py file \
  --input_file tests/files/CVE-2024-56520.txt \
  --name "Check created by time" \
  --ai_provider openai:gpt-4o \
  --created 2010-01-01T00:00:00 \
  --report_id 17ea21d3-a73d-44ec-bb12-eb1d34890027
```

## External references

```shell
python3 txt2detection.py file \
  --input_file tests/files/CVE-2024-56520.txt \
  --name "External references" \
  --external_refs txt2stix=demo1 source=id \
  --ai_provider openai:gpt-4o \
  --report_id 79be13c7-15dd-4b66-a29a-8161fca77877
```

## Reference URLs

```shell
python3 txt2detection.py file \
  --input_file tests/files/CVE-2024-56520.txt \
  --name "Reference URLs" \
  --reference_urls "https://www.google.com/" "https://www.facebook.com/" \
  --ai_provider openai:gpt-4o \
  --report_id a9928bf1-b0ab-4748-8ab8-47eb7a34ca80
```

## Check Vulmatch / CTI Butler

```shell
python3 txt2detection.py file \
  --input_file tests/files/CVE-2024-56520.txt \
  --name "Check Vulmatch / CTI Butler" \
  --ai_provider openai:gpt-4o \
  --report_id 9c78f6e4-4955-4c48-91f0-c669f744b44e
```

## Testing input txt

```shell
python3 txt2detection.py text \
  --input_text "a rule detecting suspicious logins on windows systems" \
  --name "Testing input txt" \
  --ai_provider openai:gpt-4o \
  --report_id ca20d4a1-e40d-47a9-a454-1324beff4727
```

## Check license

```shell
python3 txt2detection.py file \
  --input_file tests/files/CVE-2024-56520.txt \
  --name "Check license" \
  --ai_provider openai:gpt-4o \
  --license MIT \
  --report_id e37506ca-b3e4-45b8-8205-77b815b88d7f
```

## Check observable extraction

```shell
python3 txt2detection.py file \
  --input_file tests/files/observables.txt \
  --name "Check observables" \
  --ai_provider openai:gpt-4o \
  --report_id 4aa5924b-2081-42ed-9934-ebf200427302
```

# Manual Rule Gen

## Title

Should fail

```shell
python3 txt2detection.py sigma \
  --sigma_file tests/files/sigma-rule-no-title.yml \
  --name "No title"
```

Title, but report name is override by CLI input

```shell
python3 txt2detection.py sigma \
  --sigma_file tests/files/sigma-rule-master.yml \
  --name "A new title" \
  --report_id 272daf95-2790-4fd5-9ca6-ee8cef08315d
```

## No description

```shell
python3 txt2detection.py sigma \
  --sigma_file tests/files/sigma-rule-no-description.yml \
  --name "No description" \
  --report_id fd38cd23-93af-41ad-ab43-a6fa0ca69bf5
```

## Check that derived-from is created

```shell
python3 txt2detection.py sigma \
  --sigma_file tests/files/sigma-rule-master.yml \
  --name "Manual Rule Gen" \
  --report_id 80fc4d1c-f02c-4bff-80bf-d97490a04542
```

## Random ID

```shell
python3 txt2detection.py sigma \
  --sigma_file tests/files/sigma-rule-master.yml \
  --name "Random ID"
```

## Append related

`related` property exist, check append is correct

```shell
python3 txt2detection.py sigma \
  --sigma_file tests/files/sigma-rule-existing-related.yml \
  --name "Append related" \
  --report_id 655f0689-5209-4ad5-a6de-3f198c696060
```

## Check dates

No `date` or `modified` (expect script run time used in rule AND STIX objects)

```shell
python3 txt2detection.py sigma \
  --sigma_file tests/files/sigma-rule-no-date.yml \
  --name "No date or modified" \
  --report_id 38e0a255-66c1-48b1-a5e2-ace0b6ede336
```

Only `date` no `modified` (expect no modified in rule, STIX objects use date for mod and created)

```shell
python3 txt2detection.py sigma \
  --sigma_file tests/files/sigma-rule-one-date.yml \
  --name "One date" \
  --report_id 0b9a4d60-9020-4abb-8754-5a19bd7aaeb5
```

`date` and `modified` exists (expect STIX objects to use time in rule)

```shell
python3 txt2detection.py sigma \
  --sigma_file tests/files/sigma-rule-master.yml \
  --name "Date and modified exists" \
  --report_id e9b31ad2-44fb-450c-97f8-e3ecc653730f
```

`date` and `modified` exists but are both overwritten by cli (expect rule and STIX objects to use created/modified time passed by CLI)

```shell
python3 txt2detection.py sigma \
  --sigma_file tests/files/sigma-rule-master.yml \
  --name "Date and modified exists but are both overwritten by cli" \
  --created 2000-01-01T23:59:59 \
  --report_id 446403a3-82e2-4ae7-ae98-89c5c6a77659
```

## Check author

No author, should be autogenerated

```shell
python3 txt2detection.py sigma \
  --sigma_file tests/files/sigma-rule-no-author.yml \
  --name "No author, should be autogenerated" \
  --report_id 9fd32226-0b52-4a54-9fab-eb44320ec483
```

Author exists, should create STIX Identity applied to Indicator, Report, and SROs

```shell
python3 txt2detection.py sigma \
  --sigma_file tests/files/sigma-rule-master.yml \
  --name "Author exists" \
  --report_id 1a7de563-ff45-46f3-b5d1-e930a5eae99c
```

Author exists, but overwritten by cli

```shell
python3 txt2detection.py sigma \
  --sigma_file tests/files/sigma-rule-master.yml \
  --name "Author exists, overwritten by cli" \
  --use_identity '{"type":"identity","spec_version":"2.1","id":"identity--8ef05850-cb0d-51f7-80be-50e4376dbe99","created_by_ref":"identity--9779a2db-f98c-5f4b-8d08-8ee04e02dbb5","created":"2020-01-01T00:00:00.000Z","modified":"2020-01-01T00:00:00.000Z","name":"siemrules demo","description":"https://github.com/muchdogesec/siemrules","identity_class":"system","sectors":["technology"],"contact_information":"https://www.dogesec.com/contact/","object_marking_refs":["marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487","marking-definition--97ba4e8b-04f6-57e8-8f6e-3a0f0a7dc0fb"]}' \
  --report_id 7fd34b0f-a5fe-4ec8-aa29-ce89ee087fe8
```

No author exists created by cli

```shell
python3 txt2detection.py sigma \
  --sigma_file tests/files/sigma-rule-no-author.yml \
  --name "No author exists created by cli" \
  --use_identity '{"type":"identity","spec_version":"2.1","id":"identity--8ef05850-cb0d-51f7-80be-50e4376dbe99","created_by_ref":"identity--9779a2db-f98c-5f4b-8d08-8ee04e02dbb5","created":"2020-01-01T00:00:00.000Z","modified":"2020-01-01T00:00:00.000Z","name":"siemrules demo","description":"https://github.com/muchdogesec/siemrules","identity_class":"system","sectors":["technology"],"contact_information":"https://www.dogesec.com/contact/","object_marking_refs":["marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487","marking-definition--97ba4e8b-04f6-57e8-8f6e-3a0f0a7dc0fb"]}' \
  --report_id 84d03b6d-d27f-4392-ae9a-8fe485f3297a
```

## Check tags in rule

Attack (Tactic and Technique), CVE and TLP (Red) all exist

```shell
python3 txt2detection.py sigma \
  --sigma_file tests/files/sigma-rule-master.yml \
  --name "Attack, CVE and TLP (Red) all exist" \
  --report_id 572832e4-a8a5-435b-9945-b27097f092f5
```

Overwrite TLP

```shell
python3 txt2detection.py sigma \
  --sigma_file tests/files/sigma-rule-master.yml \
  --name "Overwrite TLP" \
  --tlp_level amber_strict \
  --report_id 599f43dc-ecaf-421c-ae01-ba8b2d705756
```

No TLP

```shell
python3 txt2detection.py sigma \
  --sigma_file tests/files/sigma-rule-no-tags.yml \
  --name "No TLP" \
  --report_id d9047840-fcb8-486c-bdf6-9bdca0e38c11
```

## Append tags

```shell
python3 txt2detection.py sigma \
  --sigma_file tests/files/sigma-rule-master.yml \
  --name "Author exists" \
  --labels "namespace.label1" "namespace.label2" \
  --report_id 9bed8a97-fe24-4552-9976-75b7e6c42851
```

## Custom labels in tag

Check Indicator + Report inherits custom tag (but not cve, attack, tlp)

```shell
python3 txt2detection.py sigma \
  --sigma_file tests/files/sigma-rule-custom-tags.yml \
  --name "Check Indicator inherits tag" \
  --report_id 4af65c32-8f6c-4a0f-9c9d-dae3cde73aa2
```

## External references

```shell
python3 txt2detection.py sigma \
  --sigma_file tests/files/sigma-rule-master.yml \
  --name "External references" \
  --external_refs txt2stix=demo1 source=id \
  --report_id e05bd145-0b28-47ba-8f8d-1b1dfb2278cb
```

## Reference URLs

```shell
python3 txt2detection.py sigma \
  --sigma_file tests/files/sigma-rule-master.yml \
  --name "Reference URLs" \
  --reference_urls "https://www.google.com/" "https://www.facebook.com/" \
  --report_id dbad3041-7ea5-4e86-8e0b-03e7db98583d
```

## Check license

Should overwrite

```shell
python3 txt2detection.py sigma \
  --sigma_file tests/files/sigma-rule-master.yml \
  --name "Check license" \
  --license BSD-3-Clause   \
  --report_id 8d858b39-0636-4f4b-bafc-3ec63264b9d2
```

Should create

```shell
python3 txt2detection.py sigma \
  --sigma_file tests/files/sigma-rule-no-license.yml \
  --name "Check license" \
  --license MIT   \
  --report_id d9fc533f-bc07-4295-b4f5-f09c41b9941d
```

## Check observable extraction

```shell
python3 txt2detection.py sigma \
  --sigma_file tests/files/sigma-rule-observables.yml \
  --name "Check observable extraction" \
  --report_id 1e71046f-2c8f-4617-908e-23f7463d350b
```

## Check level

No level in rule

```shell
python3 txt2detection.py sigma \
  --sigma_file tests/files/sigma-rule-no-level.yml \
  --name "No level in rule" \
  --level high \
  --report_id 7443a482-f7f2-4844-966b-288b1d8ad425
```

Overwrite level

```shell
python3 txt2detection.py sigma \
  --sigma_file tests/files/sigma-rule-master.yml \
  --name "Overwrite level" \
  --level high \
  --report_id c7730a33-759c-4eb0-ba38-7b1370df9ce9
```

## Check status

No status in rule, not included

```shell
python3 txt2detection.py sigma \
  --sigma_file tests/files/sigma-rule-no-status.yml \
  --name "No status in rule" \
  --report_id 6a4c842a-986f-43f0-8f3f-d98cdd36e01e
```

No status in rule should be added

```shell
python3 txt2detection.py sigma \
  --sigma_file tests/files/sigma-rule-no-status.yml \
  --name "No status in rule but should be added" \
  --status unsupported \
  --report_id c5f83c63-8a83-409b-8c43-a237987afb0f
```

Overwrite status

```shell
python3 txt2detection.py sigma \
  --sigma_file tests/files/sigma-rule-master.yml \
  --name "Overwrite status" \
  --status unsupported \
  --report_id d2d01afa-dc55-4a80-8d62-15d154450112
```