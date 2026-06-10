import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).parent
HASHES = ROOT / "data" / "seed_hashes.json"
KEYWORDS = ROOT / "data" / "keywords.json"

sys.path.insert(0, str(ROOT))
from exorcist.detection import phash

IMAGE_EXTS = {".png", ".jpg", ".jpeg", ".webp", ".gif", ".bmp"}


def load(path, default):
    return json.loads(path.read_text(encoding="utf-8")) if path.exists() else default


def dump(path, data):
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")


def images(folder, reset):
    folder = Path(folder)
    if not folder.is_dir():
        sys.exit(f"not a folder: {folder}")

    hashes = [] if reset else load(HASHES, [])
    seen = set(hashes)
    added = skipped = 0
    for f in sorted(folder.rglob("*")):
        if f.suffix.lower() not in IMAGE_EXTS:
            continue
        h = phash(f.read_bytes())
        if not h:
            skipped += 1
            continue
        if h not in seen:
            seen.add(h)
            hashes.append(h)
            added += 1

    dump(HASHES, hashes)
    print(f"added {added} new hash(es), skipped {skipped} unreadable, seed now holds {len(hashes)}")


def keywords(file, reset):
    file = Path(file)
    if not file.is_file():
        sys.exit(f"not a file: {file}")

    data = load(KEYWORDS, {"keywords": [], "invite_bait": []})
    if reset:
        data["keywords"] = []
    seen = set(data["keywords"])
    added = 0
    for line in file.read_text(encoding="utf-8").splitlines():
        word = line.strip().lower()
        if word and word not in seen:
            seen.add(word)
            data["keywords"].append(word)
            added += 1

    dump(KEYWORDS, data)
    print(f"added {added} new keyword(s), list now holds {len(data['keywords'])}")


def stats():
    words = load(KEYWORDS, {})
    print(f"seed hashes: {len(load(HASHES, []))}")
    print(f"keywords:    {len(words.get('keywords', []))}")


def main():
    parser = argparse.ArgumentParser(description="build exorcist's pretrained scam data before you deploy")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("images", help="hash a folder of scam screenshots into the seed")
    p.add_argument("folder")
    p.add_argument("--reset", action="store_true", help="replace the seed instead of adding to it")

    p = sub.add_parser("keywords", help="add scam wording from a text file, one per line")
    p.add_argument("file")
    p.add_argument("--reset", action="store_true", help="replace the keyword list instead of adding to it")

    sub.add_parser("stats", help="show how much seed data you have")

    args = parser.parse_args()
    if args.cmd == "images":
        images(args.folder, args.reset)
    elif args.cmd == "keywords":
        keywords(args.file, args.reset)
    else:
        stats()


if __name__ == "__main__":
    main()
