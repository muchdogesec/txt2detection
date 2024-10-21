from dotenv import load_dotenv

from txt2detection.__main__ import main, parse_args


load_dotenv(override=True)
args = parse_args()
main(args)
