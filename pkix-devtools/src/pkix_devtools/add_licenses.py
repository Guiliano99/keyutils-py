# SPDX-FileCopyrightText: Copyright 2026
#
# SPDX-License-Identifier: Apache-2.0

"""Add the SPDX header to every Python file under the given directories, and to every Markdown file, that lacks one.

    add-licenses [DIR ...] [--no-markdown]

The directories default to `src` and `scripts`; Markdown files are looked for in the whole repository.
"""

import argparse
import glob
import os.path
from typing import List, Optional

BASE_HEADER = """# SPDX-FileCopyrightText: Copyright 2026
#
# SPDX-License-Identifier: Apache-2.0
"""

MD_HEADER = """<!-- SPDX-FileCopyrightText: Copyright 2026
SPDX-License-Identifier: Apache-2.0 -->
"""


def add_header_to_file(path: str, header: str = BASE_HEADER) -> bool:
    """Add the SPDX header to a file unless it has one; return whether it was added."""
    with open(path, encoding="utf-8") as f:
        content = f.read()
    # REUSE-IgnoreStart
    if "SPDX-License-Identifier:" in content:
        # REUSE-IgnoreEnd
        return False
    with open(path, "w", encoding="utf-8") as f:
        if os.path.basename(path) == "__init__.py":
            f.write("# noqa D104 Missing docstring in public package" + "\n")
        f.write(header + "\n" + content)
    print(f"Header added to {path}")
    return True


def main(argv: Optional[List[str]] = None) -> int:
    """Run the tool."""
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("dirs", nargs="*", default=["src", "scripts"], help="directories with Python files")
    parser.add_argument("--no-markdown", action="store_true", help="leave the Markdown files alone")
    args = parser.parse_args(argv)
    for dir_path in args.dirs:
        for file in glob.iglob(f"{dir_path}/**/*.py", recursive=True):
            add_header_to_file(file)
    if not args.no_markdown:
        for file in glob.iglob("./**/*.md", recursive=True):
            add_header_to_file(file, MD_HEADER)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
