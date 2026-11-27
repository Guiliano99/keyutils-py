# SPDX-FileCopyrightText: Copyright 2026
#
# SPDX-License-Identifier: Apache-2.0

"""List the normative sentences of the pinned specifications as requirement items.

The manifest (`data/requirements/manifest.toml`) names the RFCs and the SHA-256 of their text. The texts are not part
of the repository: they are downloaded into `.cache/rfc/` and checked against the hash.

Every sentence of a numbered section or an appendix that contains a BCP 14 keyword (MUST, SHOULD, MAY, ...) becomes
one item in `data/requirements/items.jsonl`. The scan is mechanical, so no requirement is left out by oversight. An
item has

- `id`, `rfc`, `section`, `keywords`, `quote`: written by this script, never edited by hand;
- `actor`, `testable`, `note`: the reading of the sentence, filled in by a person. `actor` is one of the parties the
  manifest names. `testable` says whether a test of this suite can check the sentence; if not, `note` says why.

Items with `"source": "manual"` are sentences without a keyword that a test relies on. They are added by hand and this
script only checks that their quote is in the cited section.

Usage (from the repository root):
    extract-requirements --update   # add new sentences, keep the ids and the readings
    extract-requirements --check    # fail if the list and the texts disagree
"""

import argparse
import hashlib
import json
import re
import sys
import tomllib
import urllib.request
from pathlib import Path
from typing import Dict, List, Tuple

MANIFEST = Path("data/requirements/manifest.toml")
ITEMS = Path("data/requirements/items.jsonl")
CACHE = Path(".cache/rfc")

KEYWORD = re.compile(
    r"\b(MUST NOT|SHALL NOT|SHOULD NOT|NOT RECOMMENDED|MUST|REQUIRED|SHALL|SHOULD|RECOMMENDED|MAY|OPTIONAL)\b"
)
# "4.2.1.  Title", "Appendix A.  Title", "A.1.  Title" at the start of a line. Entries of the table of contents are
# indented and therefore do not match.
HEADING = re.compile(r"^(?:Appendix ([A-Z])\.|((?:[A-Z]|\d+)(?:\.\d+)*)\.)\s{2,}\S")
PAGE_FOOTER = re.compile(r"\[Page \d+\]\s*$")
PAGE_HEADER = re.compile(r"^RFC \d+\s.*\d{4}\s*$")
TABLE_BORDER = re.compile(r"^\s*\+[-=+]+\+\s*$")
TABLE_ROW = re.compile(r"^\s*\|.*\|\s*$")
BULLET = re.compile(r"^\s+(?:--|[o*+-]|\d+\.|\([a-z0-9]+\))\s+(?=\S)")
SENTENCE_END = re.compile(r"(?<=[.?!])[\"')\]]*\s+(?=[A-Z\"(\[])")
ABBREVIATION = re.compile(r"(?:\b(?:e\.g|i\.e|etc|cf|vs|Sec|No|Fig)\.)$")
# A fragment of an ASN.1 definition: its OPTIONAL is not the BCP 14 keyword.
ASN1_FIELD = re.compile(r"OPTIONAL\s*[,}]|\[\d+\]\s+(?:EXPLICIT|IMPLICIT)\b")
BOILERPLATE = "are to be interpreted as described in"


def normalise(text: str) -> str:
    """Collapse whitespace, drop table borders and unify the quotation marks, for comparing quotations."""
    text = text.replace("“", '"').replace("”", '"').replace("’", "'")
    text = re.sub(r"\+[-=+]+\+?", " ", text).replace("|", " ")
    return re.sub(r"\s+", " ", text).strip().lower()


def load_manifest(path: Path = MANIFEST) -> List[dict]:
    """Return the documents of the manifest."""
    return tomllib.loads(path.read_text(encoding="utf-8"))["document"]


def load_actors(path: Path = MANIFEST) -> List[str]:
    """Return the parties a sentence can oblige, as the manifest names them for this protocol."""
    return tomllib.loads(path.read_text(encoding="utf-8"))["actors"]


def load_text(document: dict, cache: Path = CACHE) -> str:
    """Return the text of a document, downloading it once, and fail if it is not the pinned text."""
    path = cache / f"rfc{document['rfc']}.txt"
    if not path.exists():
        if not document["url"].startswith("https://"):
            raise ValueError(f"Refusing to download from {document['url']}")
        cache.mkdir(parents=True, exist_ok=True)
        with urllib.request.urlopen(document["url"], timeout=60) as reply:  # noqa: S310 - https only, see above
            path.write_bytes(reply.read())
    data = path.read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    if digest != document["sha256"]:
        raise ValueError(f"{path} has SHA-256 {digest}, the manifest pins {document['sha256']}")
    return data.decode("utf-8-sig")


def _without_page_breaks(text: str) -> List[str]:
    """Return the lines of a paginated RFC without footers, form feeds and headers.

    A paragraph that continues on the next page is rejoined. The text gives no certain sign of that, so the next page
    is taken as a continuation if its first word starts with a lower-case letter.
    """
    lines: List[str] = []
    in_break = False
    for line in text.splitlines():
        if PAGE_FOOTER.search(line):
            while lines and not lines[-1].strip():
                lines.pop()
            in_break = True
        elif in_break and (not line.strip() or "\f" in line or PAGE_HEADER.match(line)):
            continue
        else:
            if in_break and not line.lstrip()[:1].islower():
                lines.append("")
            in_break = False
            lines.append(line)
    return lines


def split_sections(text: str) -> Dict[str, List[str]]:
    """Return {section number: lines} for the numbered sections and the appendices of an RFC text."""
    sections: Dict[str, List[str]] = {}
    current = None
    for line in _without_page_breaks(text):
        heading = HEADING.match(line)
        if heading:
            current = heading.group(1) or heading.group(2)
            sections[current] = []
        elif line and not line[0].isspace():
            current = None  # an unnumbered heading such as "Acknowledgments": not scanned
        elif current is not None:
            sections[current].append(line)
    return sections


def _units(lines: List[str]) -> List[str]:
    """Join the lines of each paragraph, list entry or table cell into one string."""
    units: List[str] = []
    current: List[str] = []
    cells: List[List[str]] = []  # the text of the table row being read, one list per column

    def flush() -> None:
        if current:
            text = current[0]
            for part in current[1:]:
                # A word that was broken after a hyphen at the end of a line is joined without a space.
                text += part if re.search(r"\w-$", text) and re.match(r"\w", part) else " " + part
            units.append(text)
            current.clear()

    def flush_row() -> None:
        units.extend(" ".join(cell) for cell in cells if cell)
        cells.clear()

    for line in lines:
        if TABLE_BORDER.match(line):
            flush()
            flush_row()
            continue
        if TABLE_ROW.match(line):
            flush()
            for column, text in enumerate(line.strip().strip("|").split("|")):
                while len(cells) <= column:
                    cells.append([])
                if text.strip():
                    cells[column].append(text.strip())
            continue
        flush_row()
        if not line.strip():
            flush()
            continue
        bullet = BULLET.match(line)
        if bullet:
            flush()
            line = line[bullet.end() :]
        current.append(line.strip())
    flush()
    flush_row()
    return units


def section_text(lines: List[str]) -> str:
    """Return the text of a section as one normalised string."""
    return normalise(" ".join(_units(lines)))


def sentences(unit: str) -> List[str]:
    """Split a paragraph into sentences."""
    out: List[str] = []
    for piece in SENTENCE_END.split(unit):
        if out and ABBREVIATION.search(out[-1]):
            out[-1] += " " + piece
        else:
            out.append(piece)
    return [s.strip() for s in out if s.strip()]


def scan(document: dict, text: str) -> List[dict]:
    """Return the sentences with a BCP 14 keyword as (not yet numbered) items, in document order."""
    found: List[dict] = []
    for section, lines in split_sections(text).items():
        for unit in _units(lines):
            for sentence in sentences(unit):
                keywords = list(dict.fromkeys(KEYWORD.findall(sentence)))
                # Decided per sentence: RFCs run prose and a "::=" definition together in one paragraph.
                if not keywords or "::=" in sentence or ASN1_FIELD.search(sentence) or BOILERPLATE in sentence:
                    continue
                found.append({"rfc": document["rfc"], "section": section, "keywords": keywords, "quote": sentence})
    return found


def read_items(path: Path = ITEMS) -> List[dict]:
    """Return the items of the list."""
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def _key(item: dict) -> Tuple[int, str, str]:
    return item["rfc"], item["section"], normalise(item["quote"])


def reconcile(
    items: List[dict], scanned: List[dict], texts: Dict[int, Dict[str, List[str]]], actors: List[str]
) -> Tuple[List[dict], List[str]]:
    """Return (items with the new sentences added, problems). Ids and readings of known items are kept."""
    problems: List[str] = []
    known = {_key(item): item for item in items}
    scanned_keys = {_key(item) for item in scanned}
    counter: Dict[int, int] = {}
    for item in items:
        counter[item["rfc"]] = max(counter.get(item["rfc"], 0), int(item["id"].rsplit("-", 1)[1]))

    merged = list(items)
    for new in scanned:
        if _key(new) in known:
            known[_key(new)]["keywords"] = new["keywords"]
            continue
        counter[new["rfc"]] = counter.get(new["rfc"], 0) + 1
        merged.append(
            {
                "id": f"rfc{new['rfc']}-{counter[new['rfc']]:03d}",
                **new,
                "source": "scan",
                "actor": "",
                "testable": None,
                "note": "",
            }
        )

    for item in merged:
        where = f"{item['id']} (RFC {item['rfc']} Section {item['section']})"
        if item.get("source") == "manual":
            section = texts.get(item["rfc"], {}).get(item["section"])
            if section is None or normalise(item["quote"]) not in section_text(section):
                problems.append(f"{where}: the quote of this manual item is not in the cited section")
        elif _key(item) not in scanned_keys:
            problems.append(f"{where}: the sentence is no longer in the text; remove the item or mark it manual")
        if item["actor"] not in actors or item["testable"] is None:
            problems.append(f"{where}: not classified (actor one of {actors}, testable true or false)")
        elif item["testable"] is False and not item["note"]:
            problems.append(f"{where}: not testable, but the note does not say why")
    merged.sort(key=lambda item: item["id"])
    return merged, problems


def main() -> int:
    """Scan the pinned texts and update or check the item list."""
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--update", action="store_true", help="add new sentences to the list")
    mode.add_argument("--check", action="store_true", help="only check, write nothing")
    parser.add_argument("--manifest", type=Path, default=MANIFEST)
    parser.add_argument("--items", type=Path, default=ITEMS)
    args = parser.parse_args()

    scanned: List[dict] = []
    texts: Dict[int, Dict[str, List[str]]] = {}
    for document in load_manifest(args.manifest):
        text = load_text(document)
        texts[document["rfc"]] = split_sections(text)
        found = scan(document, text)
        scanned.extend(found)
        print(f"RFC {document['rfc']}: {len(texts[document['rfc']])} sections, {len(found)} normative sentences")

    before = read_items(args.items)
    merged, problems = reconcile(before, scanned, texts, load_actors(args.manifest))
    added = len(merged) - len(before)
    from_scan = sum(1 for item in merged if item.get("source") != "manual")
    if from_scan != len(scanned) and not any("no longer in the text" in p for p in problems):
        problems.append(f"{from_scan} scanned items in the list, but the scan finds {len(scanned)} sentences")
    if args.check and added:
        problems.append(f"{added} sentences of the texts are not in the list; run with --update")
    if args.update:
        args.items.parent.mkdir(parents=True, exist_ok=True)
        args.items.write_text("".join(json.dumps(item, ensure_ascii=False) + "\n" for item in merged), encoding="utf-8")
        print(f"{len(merged)} items written to {args.items} ({added} new)")
    for problem in problems:
        print(f"PROBLEM: {problem}")
    print(f"{len(scanned)} sentences scanned, {len(merged)} items, {len(problems)} problems")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
