import io
import logging
import typing

from llama_index.core.output_parsers import PydanticOutputParser


if typing.TYPE_CHECKING:    
    from txt2detection.bundler import Bundler


class ParserWithLogging(PydanticOutputParser):
    def parse(self, text: str):
        f = io.StringIO()
        print("\n" * 5 + "=================start=================", file=f)
        print(text, file=f)
        print("=================close=================" + "\n" * 5, file=f)
        logging.debug(f.getvalue())
        return super().parse(text)
