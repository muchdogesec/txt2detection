## Testing input txt

Basic input

```shell
python3 txt2detection.py text \
  --input_text "a rule detecting suspicious logins on windows systems" \
  --name "Testing input txt" \
  --ai_provider openai:gpt-5 \
  --report_id ca20d4a1-e40d-47a9-a454-1324beff4727
```


## Write multiple rules

```shell
python3 txt2detection.py text \
  --input_text "Write rule to detect 1.1.1.1.\n Write a second rule to detect google.com" \
  --name "Multi rule" \
  --ai_provider openai:gpt-5 \
  --create_attack_navigator_layer \
  --report_id 3daabf35-a632-43be-a2b0-1c35a93069b1
```