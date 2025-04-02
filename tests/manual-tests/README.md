
e.g.

```shell
python3 txt2detection.py \
  --input_file tests/files/CVE-2024-56520.txt \
  --name "CVE-2024-56520" \
  --tlp_level green \
  --labels label1,label2 \
  --external_refs txt2stix=demo1 source=id \
  --ai_provider openai:gpt-4o \
  --report_id a70c4ca8-77d5-4c6f-96fb-9726ec89d242 \
  --use_identity '{"type":"identity","spec_version":"2.1","id":"identity--8ef05850-cb0d-51f7-80be-50e4376dbe63","created_by_ref":"identity--9779a2db-f98c-5f4b-8d08-8ee04e02dbb5","created":"2020-01-01T00:00:00.000Z","modified":"2020-01-01T00:00:00.000Z","name":"siemrules","description":"https://github.com/muchdogesec/siemrules","identity_class":"system","sectors":["technology"],"contact_information":"https://www.dogesec.com/contact/","object_marking_refs":["marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487","marking-definition--97ba4e8b-04f6-57e8-8f6e-3a0f0a7dc0fb"]}'
```

e.g.

```shell
python3 txt2detection.py \
  --input_file tests/files/EC2-exfil.txt \
  --name "EC2 exfil" \
  --tlp_level green \
  --ai_provider openai:gpt-4o \
  --report_id b02df393-995d-421e-b66c-721000e058d2
```

## Check TLP

```shell
python3 txt2detection.py \
  --input_file tests/files/CVE-2024-56520.txt \
  --name "Check TLP" \
  --ai_provider openai:gpt-4o \
  --tlp_level red \
  --report_id e91a49ba-f935-4844-8b37-0d5e963f0683
```

## Check custom identity

```shell
python3 txt2detection.py \
  --input_file tests/files/CVE-2024-56520.txt \
  --name "Check custom identity" \
  --ai_provider openai:gpt-4o \
  --use_identity '{"type":"identity","spec_version":"2.1","id":"identity--8ef05850-cb0d-51f7-80be-50e4376dbe63","created_by_ref":"identity--9779a2db-f98c-5f4b-8d08-8ee04e02dbb5","created":"2020-01-01T00:00:00.000Z","modified":"2020-01-01T00:00:00.000Z","name":"siemrules","description":"https://github.com/muchdogesec/siemrules","identity_class":"system","sectors":["technology"],"contact_information":"https://www.dogesec.com/contact/","object_marking_refs":["marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487","marking-definition--97ba4e8b-04f6-57e8-8f6e-3a0f0a7dc0fb"]}' \
  --report_id f6f5bcb9-095f-47fb-b286-92b6a2aee221
```

## Check confidence score

No confidence in report

```shell
python3 txt2detection.py \
  --input_file tests/files/CVE-2024-56520.txt \
  --name "No confidence in report" \
  --ai_provider openai:gpt-4o \
  --report_id 90403840-4ea8-4ef0-9ce5-0aa8195cf501
```

confidence in report

```shell
python3 txt2detection.py \
  --input_file tests/files/CVE-2024-56520.txt \
  --name "No confidence in report" \
  --ai_provider openai:gpt-4o \
  --report_id 5ab62152-3d0b-49c3-a8bc-2e8c059bf2c4 \
  --labels label1,label2
```


 \
  --labels label1,label2


## Check Vulmatch / CTI Butler

```shell
python3 txt2detection.py \
  --input_file tests/files/CVE-2024-56520.txt \
  --name "Check Vulmatch / CTI Butler" \
  --ai_provider openai:gpt-4o \
  --report_id 9c78f6e4-4955-4c48-91f0-c669f744b44e \
  --labels label1,label2
```
