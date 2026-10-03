#!/usr/bin/env python3

import re
import sys
from pathlib import Path


IF_RE = re.compile(r'^\s*#\s*if(?:def|ndef)?\b(.*)$')
ELIF_RE = re.compile(r'^\s*#\s*elif\b(.*)$')
ELSE_RE = re.compile(r'^\s*#\s*else\b')
ENDIF_RE = re.compile(r'^\s*#\s*endif\b')


def is_win32_winnt_condition(condition):
    """
    Return True if this #if condition tests _WIN32_WINNT.

    Examples matched:
        #if _WIN32_WINNT >= 0x0600
        #if (_WIN32_WINNT >= 0x0600)
        #if defined(_WIN32_WINNT) && _WIN32_WINNT >= 0x0600
    """
    return re.search(r'\b_WIN32_WINNT\b', condition) is not None


def preprocess(lines):
    output = []
    i = 0

    while i < len(lines):
        line = lines[i]

        m = IF_RE.match(line)

        if not m or not is_win32_winnt_condition(m.group(1)):
            output.append(line)
            i += 1
            continue

        # We found a top-level _WIN32_WINNT conditional.
        #
        # Collect its branches while respecting nested #if/#endif.
        branches = []
        current = []
        branch_type = "if"

        depth = 1
        i += 1

        while i < len(lines) and depth:
            line = lines[i]

            if IF_RE.match(line):
                depth += 1
                current.append(line)

            elif ENDIF_RE.match(line):
                depth -= 1

                if depth == 0:
                    branches.append((branch_type, current))
                    break

                current.append(line)

            elif depth == 1 and ELIF_RE.match(line):
                branches.append((branch_type, current))
                current = []
                branch_type = "elif"

            elif depth == 1 and ELSE_RE.match(line):
                branches.append((branch_type, current))
                current = []
                branch_type = "else"

            else:
                current.append(line)

            i += 1

        # We intentionally keep only the first (#if) branch.
        #
        # Nested conditionals in that branch are retained verbatim.
        if branches:
            output.extend(branches[0][1])

        i += 1  # Skip #endif

    return output


def main():
    if len(sys.argv) != 2:
        print(f"usage: {sys.argv[0]} FILE", file=sys.stderr)
        sys.exit(2)

    path = Path(sys.argv[1])

    with path.open("r", encoding="utf-8", newline="") as f:
        lines = f.readlines()

    result = preprocess(lines)

    with path.open("w", encoding="utf-8", newline="") as f:
        f.writelines(result)


if __name__ == "__main__":
    main()
