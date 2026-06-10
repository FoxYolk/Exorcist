import logging
import os
from pathlib import Path

from dotenv import load_dotenv

from exorcist.client import Exorcist


def main():
    load_dotenv()
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )

    token = os.environ.get("DISCORD_TOKEN")
    if not token:
        raise SystemExit("set DISCORD_TOKEN in your .env first")

    root = Path(__file__).parent
    settings = {
        "config_path": os.environ.get("EXORCIST_CONFIG") or root / "config.json",
        "keywords_path": root / "data" / "keywords.json",
        "seed_hashes_path": root / "data" / "seed_hashes.json",
        "tesseract_cmd": os.environ.get("TESSERACT_CMD") or None,
    }

    Exorcist(settings).run(token, log_handler=None)


if __name__ == "__main__":
    main()
