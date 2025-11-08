import io
import logging
import typing
import json_repair

from llama_index.core.output_parsers import PydanticOutputParser


if typing.TYPE_CHECKING:
    from txt2detection.bundler import Bundler

class BadAIOutput(Exception):
    pass


class ParserWithLogging(PydanticOutputParser):
    def parse(self, text: str):
        f = io.StringIO()
        print("\n" * 5 + "=================start=================", file=f)
        print(text, file=f)
        print("=================close=================" + "\n" * 5, file=f)
        logging.debug(f.getvalue())
        try:
            repaired_json = json_repair.repair_json(text)
            return super().parse(repaired_json)
        except Exception as e:
            logging.exception(e)
            raise BadAIOutput("Unparsable output returned by LLM model") from e