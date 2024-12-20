# txt2detection

## Overview

![txt2detection](docs/txt2detection.png)

A command line tool that takes a txt file containing threat intelligence and turns it into a detection rule.

## The problems

To illustrate the problem, lets walk through the current status quo process a human goes through when going from idea (threat TTP) to detection rule:

1. read and understand threat using their own research, aided by external sources (blogs, intel feed, etc.)
  * problems: lots of reports, threats described in a range of ways, reports contain differing data
2. understand what logs or security data can be used to detect this threat
  * problems: log schemas are unknown to analyst, TTPs often span many logs making it hard to ensure your detection rule has full coverage
3. convert the logic created in step 1 into a detection rule (SQL/SPL/KQL, whatever) to search logs identified at step 2
  * problems: hard to convert what has been understood into a logical detection rule (in a detection language an analyst might not be familiar with)
4. modify the detection rule based on new intelligence as it is discovered
  * problems: this is typically overlooked as people create and forget about rules in their detection tools

## The solution

Use the AI to process threat intelligence, create and keep them updated.

txt2detection allows a user to enter some threat intelligence as a file to considered be turned into a detection.

1. User uploads intel report
2. Based on the user input, AI prompts structured and sent to produce an intelligence rule
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

### Set variables

txt2detection has various settings that are defined in an `.env` file.

To create a template for the file:

```shell
cp .env.example .env
```

To see more information about how to set the variables, and what they do, read the `.env.markdown` file.

### Run

```shell
python3 txt2detection.py \
  --input_file FILE.txt \
  --name NAME \
  --tlp_level TLP_LEVEL \
  --labels label1,label2 \
  --created DATE \
  --use_identity \{IDENTITY JSON\} \
  --detection_language DETECTION_LANGUAGE \
  --ai_provider PROVIDER:MODEL
```

* `--input_file` (required): the file to be converted. Must be `.txt`
* `--name` (required): name of file, max 72 chars. Will be used in the STIX Report Object created.
* `--tlp_level` (optional): Options are `clear`, `green`, `amber`, `amber_strict`, `red`. Default if not passed, is `clear`.
* `--labels` (optional): comma seperated list of labels. Case-insensitive (will all be converted to lower-case). Allowed `a-z`, `0-9`. e.g.`label1,label2` would create 2 labels.
* `--created` (optional): by default all object `created` times will take the time the script was run. If you want to explicitly set these times you can do so using this flag. Pass the value in the format `YYYY-MM-DDTHH:MM:SS.sssZ` e.g. `2020-01-01T00:00:00.000Z`
* `--use_identity` (optional): can pass a full STIX 2.1 identity object (make sure to properly escape). Will be validated by the STIX2 library. If none passed, the default SIEM Rules identity will be used.
* `--detection_language_key` (required): the detection rule language you want the output to be in. You can find a list of detection language keys in `config/detection_languages.yaml`
* `ai_provider` (required): defines the `provider:model` to be used. Select one option. Currently supports:
    * Provider: `openai:`, models e.g.: `gpt-4o`, `gpt-4o-mini`, `gpt-4-turbo`, `gpt-4` ([More here](https://platform.openai.com/docs/models))
    * Provider: `anthropic:`, models e.g.: `claude-3-5-sonnet-latest`, `claude-3-5-haiku-latest`, `claude-3-opus-latest` ([More here](https://docs.anthropic.com/en/docs/about-claude/models))
    * Provider: `gemini:models/`, models: `gemini-1.5-pro-latest`, `gemini-1.5-flash-latest` ([More here](https://ai.google.dev/gemini-api/docs/models/gemini))

## Adding new detection languages

Adding a new detection language is fairly trivial. However, there is a implicit understanding the model understands the detection rule structure. Results can therefore be mixed, so it is worth testing in detail.

All you need to do is add a new record in `config/detection_languages.yaml`.

## Support

[Minimal support provided via the DOGESEC community](https://community.dogesec.com/).

## License

[Apache 2.0](/LICENSE).