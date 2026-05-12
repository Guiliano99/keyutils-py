# SPDX-FileCopyrightText: Copyright 2025
# SPDX-License-Identifier: Apache-2.0
#
# The original code is from the cmp-test-suite project:
#   https://github.com/siemens/cmp-test-suite
#  Code owner: Alexandr Railean
# This code may be modified, or just copy pasted from the original.
#

"""``python -m keyutils_py`` — print a summary of supported algorithms."""

from keyutils_py.keyutils import get_supported_pq_algorithms, get_supported_pq_stfl_algorithms


def main() -> None:
    """Print the supported algorithm families and counts."""
    print("keyutils-py — PQ + hybrid key library\n")

    print("Stateful-hash families:")
    families = get_supported_pq_stfl_algorithms()
    if not isinstance(families, dict):
        raise TypeError("get_supported_pq_stfl_algorithms() should return a dict here")
    for family, algorithms in families.items():
        print(f"  {family}: {len(algorithms)} algorithm(s)")

    print("\nPQ signature + KEM families:")
    pq = get_supported_pq_algorithms()
    if not isinstance(pq, dict):
        raise TypeError("get_supported_pq_algorithms() should return a dict here")
    for family, algorithms in pq.items():
        print(f"  {family}: {len(algorithms)} algorithm(s)")


if __name__ == "__main__":
    main()
