# File mode tests

## Check TLP

```shell
python3 txt2detection.py file \
  --input_file tests/files/CVE-2024-56520.txt \
  --name "Check TLP" \
  --ai_provider openai:gpt-5 \
  --tlp_level red \
  --report_id e91a49ba-f935-4844-8b37-0d5e963f0683
```

## Check labels

Should fail because no namespace

```shell
python3 txt2detection.py file \
  --input_file tests/files/CVE-2024-56520.txt \
  --name "Check bad labels" \
  --ai_provider openai:gpt-5 \
  --labels "label1","label_2" \
  --report_id 139d8b41-c5c8-48fa-aa25-39a54dfa1227
```

Should pass

```shell
python3 txt2detection.py file \
  --input_file tests/files/CVE-2024-56520.txt \
  --name "Check labels" \
  --ai_provider openai:gpt-5 \
  --labels "namespace.label1" "namespace.label_2" \
  --report_id a3731edf-e834-43d2-95b8-e03f37bde9ba
```

## Check special labels

Should fail because disallowed tag

```shell
python3 txt2detection.py file \
  --input_file tests/files/CVE-2024-56520.txt \
  --name "Disallowed tag" \
  --ai_provider openai:gpt-5 \
  --labels "tlp.red" \
  --report_id a6f2aaff-4e33-4280-bb01-ab1bd3b95362
```

Should have cve tag and matching vulnerability object

```shell
python3 txt2detection.py file \
  --input_file tests/files/CVE-2024-56520.txt \
  --name "CVE tags" \
  --ai_provider openai:gpt-5 \
  --labels "cve.2025-3593" \
  --report_id fab3707e-00fc-4f35-9d6d-e72dc0b6ba08
```

Should have attack tags and matching attack pattern and x-mitre-tactic objects

```shell
python3 txt2detection.py file \
  --input_file tests/files/CVE-2024-56520.txt \
  --name "ATT&CK tags tag" \
  --ai_provider openai:gpt-5 \
  --labels "attack.t1071.001" "attack.command-and-control" \
  --report_id 940e8807-381e-41df-a27e-08914bafd93c
```

## Check custom identity

```shell
python3 txt2detection.py file \
  --input_file tests/files/CVE-2024-56520.txt \
  --name "Check custom identity" \
  --ai_provider openai:gpt-5 \
  --use_identity '{"type":"identity","spec_version":"2.1","id":"identity--8ef05850-cb0d-51f7-80be-50e4376dbe63","created_by_ref":"identity--9779a2db-f98c-5f4b-8d08-8ee04e02dbb5","created":"2020-01-01T00:00:00.000Z","modified":"2020-01-01T00:00:00.000Z","name":"siemrules","description":"https://github.com/muchdogesec/siemrules","identity_class":"system","sectors":["technology"],"contact_information":"https://www.dogesec.com/contact/","object_marking_refs":["marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487","marking-definition--97ba4e8b-04f6-57e8-8f6e-3a0f0a7dc0fb"]}' \
  --report_id f6f5bcb9-095f-47fb-b286-92b6a2aee221
```

## Check created by time

```shell
python3 txt2detection.py file \
  --input_file tests/files/CVE-2024-56520.txt \
  --name "Check created by time" \
  --ai_provider openai:gpt-5 \
  --created 2010-01-01T00:00:00 \
  --report_id 17ea21d3-a73d-44ec-bb12-eb1d34890027
```

## External references

```shell
python3 txt2detection.py file \
  --input_file tests/files/CVE-2024-56520.txt \
  --name "External references" \
  --external_refs txt2stix=demo1 source=id \
  --ai_provider openai:gpt-5 \
  --report_id 79be13c7-15dd-4b66-a29a-8161fca77877
```

## Reference URLs

```shell
python3 txt2detection.py file \
  --input_file tests/files/CVE-2024-56520.txt \
  --name "Reference URLs" \
  --reference_urls "https://www.google.com/" "https://www.facebook.com/" \
  --ai_provider openai:gpt-5 \
  --report_id a9928bf1-b0ab-4748-8ab8-47eb7a34ca80
```

## Check Vulmatch / CTI Butler

```shell
python3 txt2detection.py file \
  --input_file tests/files/CVE-2024-56520.txt \
  --name "Check Vulmatch / CTI Butler" \
  --ai_provider openai:gpt-5 \
  --report_id 9c78f6e4-4955-4c48-91f0-c669f744b44e
```

## Check license

```shell
python3 txt2detection.py file \
  --input_file tests/files/CVE-2024-56520.txt \
  --name "Check license" \
  --ai_provider openai:gpt-5 \
  --license MIT \
  --report_id e37506ca-b3e4-45b8-8205-77b815b88d7f
```

## Check observable extraction

```shell
python3 txt2detection.py file \
  --input_file tests/files/observables.txt \
  --name "Check observables" \
  --ai_provider openai:gpt-5 \
  --report_id 4aa5924b-2081-42ed-9934-ebf200427302
```
