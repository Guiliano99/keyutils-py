# SPDX-FileCopyrightText: Copyright 2026
#
# SPDX-License-Identifier: Apache-2.0

"""Check that the test cases, the requirement items and the specification texts agree.

For every test case of the Robot Framework suites the script reads

- the requirement level from the test name (MUST, SHOULD, ...),
- the cited sections from the "RFC <n> Section <s>" statements of the documentation,
- the quotations of the documentation (in double quotes),
- the requirement items from the `item-<id>` tags.

It reports as a problem

- a test name that occurs twice, a test without a level, without a cited section or without an item tag,
- a tag that names no item, and an item from a section that the test does not cite,
- a quotation that is not verbatim in one of the cited sections (whitespace aside),
- a level that is not a keyword of one of the items of the test, unless the test is tagged `interpretation` or
  `ambiguous` (the level is then marked with `*`),
- an item that has a test but is recorded as not testable.

It writes the trace table (TSV), in which a test keeps its id once it has one, and with `--coverage` the tables
between the `BEGIN GENERATED` and `END GENERATED` markers of the coverage document. With `--check` nothing is
written and the script also fails if one of these files is not up to date.

The status of an item is not stored: it is `implemented` if a test carries its tag, `planned` if it is testable and
has no test, and `skipped` if it is not testable (the note of the item says why).

Usage (from the repository root):
    traceability --id-prefix NAME [--coverage FILE] [--check]
"""

import argparse
import re
import sys
import textwrap
from pathlib import Path
from typing import Dict, List, Set, Tuple

from pkix_devtools.extract_requirements import (
    ITEMS,
    MANIFEST,
    load_manifest,
    load_text,
    normalise,
    read_items,
    section_text,
    split_sections,
)

# BCP 14 keywords that mean the same, by the word used in test names.
LEVEL_OF_KEYWORD = {
    "MUST": "MUST",
    "SHALL": "MUST",
    "REQUIRED": "MUST",
    "MUST NOT": "MUST NOT",
    "SHALL NOT": "MUST NOT",
    "SHOULD": "SHOULD",
    "RECOMMENDED": "SHOULD",
    "SHOULD NOT": "SHOULD NOT",
    "NOT RECOMMENDED": "SHOULD NOT",
    "MAY": "MAY",
    "OPTIONAL": "MAY",
}
LEVELS = ("MUST NOT", "SHOULD NOT", "MUST", "SHOULD", "MAY")
# "RFC <n> Section 4.2.1", "Appendix A.1", "X.690 Section 11.5": an optional document, then the section.
CITATION = re.compile(r"(?:(RFC\s?\d+|[A-Z]+\.\d+),?\s+)?(?:Sections?|Appendix)\s+([A-Z](?:\.\d+)*|\d+(?:\.\d+)*)")
MIN_FRAGMENT = 14  # shorter quotations are single terms such as "unauthorized"
GENERATED = "<!-- {edge} GENERATED: {name} -->"


def parse_robot(path: Path) -> List[dict]:
    """Return the test cases of one .robot file with name, documentation and tags."""
    cases: List[dict] = []
    current = None
    in_tests = False
    setting = ""  # the setting that a "..." line continues: "doc", "tags" or neither
    for raw in path.read_text(encoding="utf-8").splitlines():
        text = raw.strip()
        if raw.startswith("*** "):
            in_tests, current = raw.startswith("*** Test Cases"), None
        elif not in_tests or not text or text.startswith("#"):
            continue
        elif not raw[0].isspace():
            current = {"name": text, "doc": "", "tags": [], "suite": path.name}
            cases.append(current)
            setting = ""
        elif current is None:
            continue
        elif text.startswith("[Documentation]"):
            current["doc"], setting = text.split("]", 1)[1].strip(), "doc"
        elif text.startswith("[Tags]"):
            current["tags"], setting = _cells(text.split("]", 1)[1]), "tags"
        elif text.startswith("...") and setting == "doc":
            current["doc"] += " " + text[3:].strip()
        elif text.startswith("...") and setting == "tags":
            current["tags"] += _cells(text[3:])
        else:
            setting = ""
    return cases


def _cells(text: str) -> List[str]:
    """Return the cells of a Robot Framework line, which two or more spaces or a tab separate."""
    return [cell for cell in re.split(r"\s{2,}|\t", text.strip()) if cell]


def level_of(case: dict) -> str:
    """Return the requirement level named in the test name, or an empty string."""
    return next((level for level in LEVELS if re.search(rf"\b{level}\b", case["name"])), "")


def anchors_of(doc: str) -> List[Tuple[int, str]]:
    """Return the (RFC number, section) pairs that a documentation cites.

    A section without a document ("... and Section 4.2.1 says ...") belongs to the RFC named last. Sections of
    other documents (X.690) and everything inside quotation marks, which is text of the specification, are left out.
    """
    prose = " ".join(doc.replace("“", '"').replace("”", '"').split('"')[0::2])
    anchors: List[Tuple[int, str]] = []
    current = None
    for document, section in CITATION.findall(prose):
        if document.startswith("RFC"):
            current = int(re.sub(r"\D", "", document))
        elif document:
            continue
        if current is not None and (current, section) not in anchors:
            anchors.append((current, section))
    return anchors


def fragments_of(doc: str) -> List[str]:
    """Return the quotations of a documentation that are long enough to be checked."""
    parts = doc.replace("“", '"').replace("”", '"').split('"')
    pieces = [piece for quoted in parts[1::2] for piece in re.split(r"\[\.\.\.\]", quoted)]
    return [piece.strip() for piece in pieces if len(normalise(piece).strip(" .,;:")) >= MIN_FRAGMENT]


def replace_generated(text: str, name: str, body: str) -> str:
    """Return `text` with the block between the markers of `name` replaced by `body`."""
    begin, end = GENERATED.format(edge="BEGIN", name=name), GENERATED.format(edge="END", name=name)
    if text.count(begin) != 1 or text.count(end) != 1:
        raise ValueError(f"The coverage document needs exactly one '{begin}' and one '{end}'")
    head, rest = text.split(begin)
    return f"{head}{begin}\n\n{body.strip()}\n\n{end}{rest.split(end)[1]}"


def check(cases: List[dict], items: Dict[str, dict], sections: Dict[int, Dict[str, str]]) -> List[str]:
    """Fill `level`, `anchors`, `items` of every case and return the problems."""
    problems: List[str] = []
    names = [case["name"] for case in cases]
    problems += [f"duplicate test name: {name}" for name in sorted({n for n in names if names.count(n) > 1})]
    for case in cases:
        where = f"{case['suite']}: {case['name']}"
        case["items"] = [tag[len("item-") :] for tag in case["tags"] if tag.startswith("item-")]
        case["anchors"] = anchors_of(case["doc"])
        cited = [anchor for anchor in case["anchors"] if anchor[0] in sections]
        inferred = bool({"interpretation", "ambiguous"} & set(case["tags"]))
        level = level_of(case)
        case["level"] = level + ("*" if inferred else "")

        if not level:
            problems.append(f"{where}: no requirement level in the test name")
        if not case["doc"].startswith("According to"):
            problems.append(f"{where}: the documentation does not start with 'According to'")
        if not cited:
            problems.append(f"{where}: the documentation cites no section of the pinned specifications")
        for rfc, section in cited:
            if section not in sections[rfc]:
                problems.append(f"{where}: RFC {rfc} has no Section {section}")
        if not case["items"]:
            problems.append(f"{where}: no item-<id> tag")

        haystack = " ".join(sections[rfc].get(section, "") for rfc, section in cited)
        fragments = fragments_of(case["doc"])
        if not fragments:
            problems.append(f"{where}: the documentation contains no quotation")
        for fragment in fragments:
            if normalise(fragment).strip(" .,;:") not in haystack:
                problems.append(f"{where}: not verbatim in the cited sections: {fragment[:80]!r}")

        keywords: Set[str] = set()
        for item_id in case["items"]:
            item = items.get(item_id)
            if item is None:
                problems.append(f"{where}: unknown item {item_id}")
                continue
            keywords |= {LEVEL_OF_KEYWORD[keyword] for keyword in item["keywords"]}
            if (item["rfc"], item["section"]) not in cited:
                problems.append(
                    f"{where}: item {item_id} is from RFC {item['rfc']} Section {item['section']}, "
                    "which the documentation does not cite"
                )
            if not item["testable"]:
                problems.append(f"{where}: item {item_id} has a test but is recorded as not testable")
        if level and not inferred and case["items"] and level not in keywords:
            problems.append(
                f"{where}: the test name says {level}, its items say {sorted(keywords)}; "
                "rename the test or tag it `interpretation`"
            )
    return problems


def trace_rows(cases: List[dict], previous: Dict[str, str], prefix: str) -> List[Tuple[str, ...]]:
    """Return the rows of the trace table. A test keeps its id; a new test gets the next free number."""
    numbers = [int(test_id.rsplit("-", 1)[1]) for test_id in previous.values()]
    next_number = max(numbers, default=0) + 1
    rows = []
    for case in cases:
        if case["name"] not in previous:
            previous[case["name"]] = f"{prefix}-{next_number:03d}"
            next_number += 1
        case["id"] = previous[case["name"]]
        anchors = ",".join(f"RFC{rfc}#{section}" for rfc, section in case["anchors"])
        rows.append((case["id"], case["level"], anchors, ",".join(case["items"]), case["suite"], case["name"]))
    return sorted(rows)


def tests_table(cases: List[dict]) -> str:
    """Return the test cases per suite as Markdown."""
    out: List[str] = []
    for suite in dict.fromkeys(case["suite"] for case in cases):
        out += [f"### `{suite}`", "", "| ID | Level | Test case | Source | Items |", "|---|---|---|---|---|"]
        for case in sorted((c for c in cases if c["suite"] == suite), key=lambda c: c["id"]):
            source = ", ".join(f"RFC {rfc} {section}" for rfc, section in case["anchors"])
            out.append(f"| {case['id']} | {case['level']} | {case['name']} | {source} | {', '.join(case['items'])} |")
        out.append("")
    return "\n".join(out)


def requirements_table(cases: List[dict], items: Dict[str, dict], titles: Dict[int, str]) -> str:
    """Return the status of every item per specification as Markdown."""
    tests_of: Dict[str, List[str]] = {}
    for case in cases:
        for item_id in case["items"]:
            tests_of.setdefault(item_id, []).append(case["id"])

    def status(item: dict) -> str:
        if item["id"] in tests_of:
            return "implemented"
        return "planned" if item["testable"] else "skipped"

    out = ["| Specification | Items | Implemented | Planned | Skipped |", "|---|---|---|---|---|"]
    for rfc in titles:
        own = [status(item) for item in items.values() if item["rfc"] == rfc]
        out.append(
            f"| RFC {rfc} | {len(own)} | {own.count('implemented')} | {own.count('planned')} | {own.count('skipped')} |"
        )
    for rfc, title in titles.items():
        out += [
            "",
            f"### RFC {rfc}: {title}",
            "",
            "| Item | Section | Level | Actor | Status | Tests, or the reason |",
            "|---|---|---|---|---|---|",
        ]
        for item in (i for i in items.values() if i["rfc"] == rfc):
            detail = ", ".join(sorted(tests_of.get(item["id"], []))) or item["note"]
            quote = textwrap.shorten(item["quote"], width=110, placeholder=" ...")  # cuts between words
            out.append(
                f"| {item['id']} | {item['section']} | {'/'.join(item['keywords'])} | {item['actor']} | "
                f"{status(item)} | {detail} |"
            )
            out.append(f"| | | | | | *{quote.replace('|', '/')}* |")
    return "\n".join(out)


def main() -> int:
    """Check the tests against the items and the texts and write the tables."""
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--tests", type=Path, default=Path("tests"))
    parser.add_argument("--items", type=Path, default=ITEMS)
    parser.add_argument("--manifest", type=Path, default=MANIFEST)
    parser.add_argument("--tsv", type=Path, default=Path("data/requirements/test_trace.tsv"))
    parser.add_argument("--id-prefix", required=True, help="prefix of the test ids, for example the protocol name")
    parser.add_argument("--coverage", type=Path, help="coverage document whose generated tables are updated")
    parser.add_argument("--check", action="store_true", help="write nothing; fail if a file is not up to date")
    args = parser.parse_args()

    documents = load_manifest(args.manifest)
    sections = {
        d["rfc"]: {name: section_text(lines) for name, lines in split_sections(load_text(d)).items()} for d in documents
    }
    items = {item["id"]: item for item in read_items(args.items)}
    cases = [case for path in sorted(args.tests.glob("*.robot")) for case in parse_robot(path)]
    problems = check(cases, items, sections)

    previous: Dict[str, str] = {}
    if args.tsv.exists():
        for line in args.tsv.read_text(encoding="utf-8").splitlines()[1:]:
            columns = line.split("\t")
            previous[columns[5]] = columns[0]
    header = "ID\tlevel\tanchors\titems\tsuite\ttest case"
    rows = trace_rows(cases, previous, args.id_prefix)
    outputs = {args.tsv: header + "\n" + "\n".join("\t".join(row) for row in rows) + "\n"}
    if args.coverage:
        text = args.coverage.read_text(encoding="utf-8")
        text = replace_generated(text, "tests", tests_table(cases))
        outputs[args.coverage] = replace_generated(
            text, "requirements", requirements_table(cases, items, {d["rfc"]: d["title"] for d in documents})
        )

    for path, content in outputs.items():
        current = path.read_text(encoding="utf-8") if path.exists() else None
        if current == content:
            continue
        if args.check:
            problems.append(f"{path} is not up to date; run without --check")
        else:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content, encoding="utf-8")
            print(f"written: {path}")

    used = {item_id for case in cases for item_id in case["items"]} & set(items)
    planned = sum(1 for item in items.values() if item["testable"] and item["id"] not in used)
    print(
        f"{len(cases)} test cases, {len(items)} items: {len(used)} implemented, {planned} planned, "
        f"{len(items) - len(used) - planned} skipped"
    )
    for problem in problems:
        print(f"PROBLEM: {problem}")
    print(f"{len(problems)} problems")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
