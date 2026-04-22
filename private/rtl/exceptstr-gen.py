#!/usr/bin/env python3

# This file generates the RtlpExceptionCodeToString routine which converts
# a numerical NTSTATUS code into its definition name

import re
import sys

# Match:
# #define ANY_NAME ((NTSTATUS)0x12345678UL)
DEFINE_RE = re.compile(
    r'^\s*#define\s+'
    r'([A-Za-z0-9_]+)\s+'          # macro name
    r'\(\(NTSTATUS\)\s*'           # ((NTSTATUS)
    r'(0x[0-9A-Fa-f]+)'            # hex value
    r'[ULul]*\)'                   # optional UL, etc, then ))
)

def parse_ntstatus(file_path):
    entries = {}

    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            m = DEFINE_RE.match(line)
            if not m:
                continue

            name = m.group(1)
            value = int(m.group(2), 16)

            # Deduplicate by value: keep first name seen
            if value not in entries:
                entries[value] = name

    return entries


def generate_function(entries, out):
    out.write("/* Auto-generated from ntstatus.h */\n")
    out.write("static PCSTR RtlpExceptionCodeToString(IN ULONG ExceptionCode)\n")
    out.write("{\n")
    out.write("    switch (ExceptionCode) {\n")

    for value in sorted(entries):
        name = entries[value]
        out.write(f"    case {name}:\n")
        out.write(f'        return "{name}";\n')

    out.write("    default:\n")
    out.write('        return "???";\n')
    out.write("    }\n")
    out.write("}\n")


def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <ntstatus.h> [output.c]")
        sys.exit(1)

    input_file = sys.argv[1]
    entries = parse_ntstatus(input_file)

    if len(sys.argv) >= 3:
        output_file = sys.argv[2]
        with open(output_file, 'w', encoding='utf-8') as out:
            generate_function(entries, out)
    else:
        # fallback to stdout
        generate_function(entries, sys.stdout)


if __name__ == "__main__":
    main()
