## Testing input txt

Basic input

```shell
python3 txt2detection.py text \
  --input_text "A rule detecting suspicious logins on windows systems because of multiple failed authentication attempts." \
  --name "Testing input txt" \
  --ai_provider openai:gpt-5 \
  --create_attack_navigator_layer \
  --report_id ca20d4a1-e40d-47a9-a454-1324beff4727
```

## Write multiple rules and tag them with ATT&CK/CVE tags

```shell
python3 txt2detection.py text \
  --input_text "Write rule to detect 1.1.1.1.\n Write a second rule to detect google.com. The rule detects CVE-2021-1675 and the ATT&CK Technique T1566" \
  --name "Multi rule" \
  --ai_provider openai:gpt-5 \
  --create_attack_navigator_layer \
  --report_id 3daabf35-a632-43be-a2b0-1c35a93069b1
```