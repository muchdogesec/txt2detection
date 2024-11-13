
```shell
python3 txt2detection.py \
  --input_file tests/files/lynx-ransomware.txt \
  --name "lynx ransomware" \
  --tlp_level green \
  --labels label1,label2 \
  --products_in_stack google_cloud_platform \
  --detection_language spl
```