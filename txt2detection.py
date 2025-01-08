from dotenv import load_dotenv

from txt2detection.__main__ import main, parse_args

import logging
import os
import sys
from dotenv import load_dotenv

from txt2detection.__main__ import main, parse_args


if __name__ == '__main__':
    load_dotenv(override=True)
    args = parse_args()
    if not os.getenv('CTIBUTLER_BASE_URL'):
        logging.fatal("CTIBUTLER_BASE_URL env not set, exiting...")
        sys.exit(11)
    main(args)
