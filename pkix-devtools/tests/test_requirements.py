# SPDX-FileCopyrightText: Copyright 2026
#
# SPDX-License-Identifier: Apache-2.0

"""Unit tests of `pkix_devtools.extract_requirements` and `pkix_devtools.traceability`.

The sample text is made up. Each case is a shape of RFC text on which an earlier version of the scan went wrong.
"""

import tempfile
import unittest
from pathlib import Path

from pkix_devtools import extract_requirements as er
from pkix_devtools import traceability as tr

DOCUMENT = {"rfc": 1}

PAGINATED = """\
1.  Introduction

   The server MUST answer.  In addition, the answer:

   -  MUST carry the answerTime January 1, 1970, and

   -- optional parts, which MAY be left out by the server



Author                       Standards Track                    [Page 1]
\f
RFC 1                            Sample                        June 2013


   Upon receipt, the server decides.  A client that sends a request
   SHOULD wait for



Author                       Standards Track                    [Page 2]
\f
RFC 1                            Sample                        June 2013


   the answer before it sends the next one.

2.  Syntax

   A client MAY name the kinds it understands.  To do so, it SHOULD use
   the kind extension.

   id-kind OBJECT IDENTIFIER ::= { id-sample 4 }

   Answer ::= SEQUENCE {
       version   [0] EXPLICIT Version DEFAULT v1,
                     -- as specified in Section 4.1.  [RFC1]
       kinds     [1] EXPLICIT Kinds OPTIONAL }

   The key words "MUST" and "MAY" are to be interpreted as described in
   BCP 14.

   +========+=============================================+
   | Field  | Description                                 |
   +========+=============================================+
   | Tag    | A string that names the version.  It is     |
   |        | RECOMMENDED that the tag be the hash of the |
   |        | answer.                                     |
   +--------+---------------------------------------------+

Acknowledgments

   The authors MUST thank everybody.
"""


class TestScan(unittest.TestCase):
    """The scan of a specification text."""

    @classmethod
    def setUpClass(cls):
        cls.found = er.scan(DOCUMENT, PAGINATED)
        cls.quotes = [item["quote"] for item in cls.found]

    def test_sentences_with_a_keyword_are_listed_per_section(self):
        """
        GIVEN a text with two numbered sections and an unnumbered one.
        WHEN it is scanned.
        THEN the sentences with a keyword are listed with their section, and the unnumbered section is left out.
        """
        self.assertEqual({item["section"] for item in self.found}, {"1", "2"})
        self.assertIn("The server MUST answer.", self.quotes)
        self.assertNotIn("The authors MUST thank everybody.", self.quotes)

    def test_list_entry_with_mixed_case_words_is_kept(self):
        """
        GIVEN a list entry whose words are mostly identifiers and names.
        WHEN it is scanned.
        THEN it is listed, and so is an entry introduced by two hyphens.
        """
        self.assertIn("MUST carry the answerTime January 1, 1970, and", self.quotes)
        self.assertIn("optional parts, which MAY be left out by the server", self.quotes)

    def test_paragraph_is_rejoined_across_a_page_break_only_if_it_continues(self):
        """
        GIVEN a page that starts with a capital letter and one that starts in the middle of a sentence.
        WHEN the text is scanned.
        THEN only the second is joined to the text before the page break.
        """
        self.assertIn("A client that sends a request SHOULD wait for the answer before it sends the next one.",
                      self.quotes)
        self.assertFalse(any("left out by the server Upon" in quote for quote in self.quotes))

    def test_asn1_is_not_a_requirement_but_the_prose_next_to_it_is(self):
        """
        GIVEN prose followed by ASN.1 definitions, one of them with the ASN.1 keyword OPTIONAL.
        WHEN the text is scanned.
        THEN the two sentences of the prose are listed and nothing of the ASN.1 is.
        """
        self.assertIn("A client MAY name the kinds it understands.", self.quotes)
        self.assertIn("To do so, it SHOULD use the kind extension.", self.quotes)
        self.assertFalse(any("OPTIONAL" in item["keywords"] for item in self.found))

    def test_boilerplate_is_skipped_and_table_cells_are_read_cell_by_cell(self):
        """
        GIVEN the BCP 14 boilerplate and a table whose second column holds a recommendation.
        WHEN the text is scanned.
        THEN the boilerplate is not listed and the recommendation is one clean sentence.
        """
        self.assertFalse(any("are to be interpreted" in quote for quote in self.quotes))
        self.assertIn("It is RECOMMENDED that the tag be the hash of the answer.", self.quotes)


class TestReconcile(unittest.TestCase):
    """Merging a scan into the list."""

    def test_known_items_keep_id_and_reading_and_new_ones_must_be_classified(self):
        """
        GIVEN a list with one classified item and a scan that finds that sentence and a new one.
        WHEN they are reconciled.
        THEN the known item is unchanged, the new one gets the next id, and it is reported as not classified.
        """
        scanned = er.scan(DOCUMENT, "1.  One\n\n   The server MUST answer.  The client MAY ask.\n")
        known = {"id": "rfc1-007", **scanned[0], "source": "scan", "actor": "server", "testable": True, "note": ""}
        merged, problems = er.reconcile([dict(known)], scanned, {1: {"1": []}}, ["server", "client"])
        self.assertEqual(merged[0], known)
        self.assertEqual(merged[1]["id"], "rfc1-008")
        self.assertEqual(len(problems), 1)
        self.assertIn("rfc1-008", problems[0])

    def test_item_whose_sentence_is_gone_is_reported(self):
        """
        GIVEN a scanned item whose sentence is no longer in the text.
        WHEN the list is reconciled.
        THEN the item is reported, not dropped.
        """
        gone = {"id": "rfc1-001", "rfc": 1, "section": "1", "keywords": ["MUST"], "quote": "It MUST vanish.",
                "source": "scan", "actor": "server", "testable": True, "note": ""}
        merged, problems = er.reconcile([gone], [], {1: {"1": []}}, ["server"])
        self.assertEqual(len(merged), 1)
        self.assertTrue(any("no longer in the text" in problem for problem in problems))


class TestTraceability(unittest.TestCase):
    """Reading the documentation of a test case."""

    def test_section_without_document_belongs_to_the_rfc_named_last(self):
        """
        GIVEN a documentation that names an RFC once and then only sections, another standard, and a quotation
              that itself mentions a section.
        WHEN the cited sections are read.
        THEN the bare sections belong to that RFC, and neither the other standard nor the quotation counts.
        """
        doc = ('According to RFC 1234 Section 4.2, "as specified in Section 9.9 of [RFC5]", and Section 2.3 adds '
               'more. X.690 Section 11.5 forbids it. RFC 5678 Appendix A.1 agrees.')
        self.assertEqual(tr.anchors_of(doc), [(1234, "4.2"), (1234, "2.3"), (5678, "A.1")])

    def test_documentation_and_tags_may_continue_on_the_next_line(self):
        """
        GIVEN a test case whose documentation and whose tags each continue on a second line.
        WHEN the suite file is parsed.
        THEN both lines of each are read, and the keyword calls after them are not.
        """
        with tempfile.TemporaryDirectory() as tmp:
            suite = Path(tmp) / "s.robot"
            suite.write_text("*** Test Cases ***\nServer MUST Answer\n    [Documentation]    According to it,\n"
                             "    ...    the server answers.\n    [Tags]    positive    item-rfc1-001\n"
                             "    ...    item-rfc1-002\n    Log    done\n    ...    more\n", encoding="utf-8")
            (case,) = tr.parse_robot(suite)
        self.assertEqual(case["doc"], "According to it, the server answers.")
        self.assertEqual(case["tags"], ["positive", "item-rfc1-001", "item-rfc1-002"])

    def test_quotations_are_split_at_elisions_and_short_ones_are_dropped(self):
        """
        GIVEN a documentation with a long quotation that has an elision and a quotation of one word.
        WHEN the quotations are read.
        THEN the two halves of the long one are returned and the single word is not.
        """
        doc = 'According to it, "the first half of the sentence [...] and the second half of it", status "good".'
        self.assertEqual(tr.fragments_of(doc), ["the first half of the sentence", "and the second half of it"])

    def test_level_must_be_a_keyword_of_an_item_unless_the_test_says_it_is_inferred(self):
        """
        GIVEN a test named MUST whose item is a MAY sentence, once plain and once tagged `interpretation`.
        WHEN the tests are checked.
        THEN only the plain one is reported.
        """
        items = {"rfc1-001": {"id": "rfc1-001", "rfc": 1, "section": "1", "keywords": ["MAY"],
                              "quote": "The client MAY ask twice.", "testable": True}}
        sections = {1: {"1": er.normalise("The client MAY ask twice.")}}

        def case(name, tags):
            return {"name": name, "suite": "s.robot", "tags": tags + ["item-rfc1-001"],
                    "doc": 'According to RFC 1 Section 1, "The client MAY ask twice."'}

        problems = tr.check([case("Server MUST Answer Twice", []),
                             case("Server MUST Answer Again", ["interpretation"])], items, sections)
        self.assertEqual(len(problems), 1)
        self.assertIn("Server MUST Answer Twice", problems[0])

    def test_generated_block_is_replaced_between_its_markers(self):
        """
        GIVEN a document with a generated block.
        WHEN the block is replaced.
        THEN only the text between the markers changes.
        """
        text = "before\n<!-- BEGIN GENERATED: tests -->\nold\n<!-- END GENERATED: tests -->\nafter\n"
        new = tr.replace_generated(text, "tests", "new table")
        self.assertEqual(new, "before\n<!-- BEGIN GENERATED: tests -->\n\nnew table\n\n<!-- END GENERATED: tests -->\nafter\n")
        self.assertEqual(tr.replace_generated(new, "tests", "new table"), new)


if __name__ == "__main__":
    unittest.main()
