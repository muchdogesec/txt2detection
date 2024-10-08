## Log generation

Note, all of these log samples have been generated using a simple prompt:

> I am building software that will parse different types of logs. To begin with I first need to understand what each log format looks like. To help me achieve this, can you print an example of <LOG TYPE> logs with 20 sample entries. Do not print anything else except the log file unless you do not understand the log type I've requested, in which case please respond with; I don't know that log type.

Given the method of generation, it should be assumed the log samples contain errors

## logs.conf

When adding a new log sample, be sure to add a record for it in `config/logs.yaml` so that it can be used to create detection rules