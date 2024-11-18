
```shell
python3 txt2detection.py \
  --input_file tests/files/CVE-2024-1212.txt \
  --name "lynx ransomware" \
  --tlp_level green \
  --labels label1,label2 \
  --detection_language spl \
  --ai_provider openai:gpt-4o
```