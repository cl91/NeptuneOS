import re
import sys

# --- REGEX PATTERNS ----------------------------------------------------------

# #define AGP_WMI_STD_DATA_GUID {0x8c27fbed,0x1c7b,0x47e4,{0xa6,0x49,0x0e,0x38,0x9d,0x3a,0xda,0x4f}}
macro_guid_re = re.compile(
    r'#define\s+([A-Za-z_][A-Za-z0-9_]*)\s*'
    r'\{\s*(0x[0-9a-fA-F]+)\s*,\s*(0x[0-9a-fA-F]+)\s*,\s*(0x[0-9a-fA-F]+)\s*,\s*'
    r'\{\s*((?:0x[0-9a-fA-F]+\s*,\s*){7}0x[0-9a-fA-F]+)\s*\}\s*\}',
    re.MULTILINE
)

# DEFINE_GUID(Name, 0x8c27fbed, 0x1c7b, 0x47e4, 0xa6, 0x49, 0x0e, 0x38, 0x9d, 0x3a, 0xda, 0x4f);
define_guid_re = re.compile(
    r'DEFINE_GUID\s*\(\s*([A-Za-z_][A-Za-z0-9_]*)\s*,\s*'
    r'(0x[0-9a-fA-F]+)\s*,\s*(0x[0-9a-fA-F]+)\s*,\s*(0x[0-9a-fA-F]+)\s*,\s*'
    r'((?:0x[0-9a-fA-F]+\s*,\s*){7}0x[0-9a-fA-F]+)\s*\);',
    re.MULTILINE
)

# --- GUID NORMALIZATION ------------------------------------------------------

def normalize_guid(first, second, third, last8):
    """
    Create a canonical GUID string so both patterns can be compared.
    """
    last = [x.strip() for x in last8.split(',')]
    return f"{first.lower()}-{second.lower()}-{third.lower()}-" + "-".join(x.lower() for x in last)

# --- MAIN --------------------------------------------------------------------

def process_header(input_text):
    macro_guids = {}
    define_guids = []

    # Parse macro GUIDs
    for m in macro_guid_re.finditer(input_text):
        name = m.group(1)
        canonical = normalize_guid(m.group(2), m.group(3), m.group(4), m.group(5))
        macro_guids[canonical] = name

    # Parse DEFINE_GUID
    for m in define_guid_re.finditer(input_text):
        define_guids.append({
            "full_match": m.group(0),
            "name": m.group(1),
            "canonical": normalize_guid(m.group(2), m.group(3), m.group(4), m.group(5))
        })

    # Rewrite duplicates
    output = input_text
    for g in define_guids:
        if g["canonical"] in macro_guids:
            macro_name = macro_guids[g["canonical"]]
            replacement = f"DEFINE_WMI_GUID({g['name']}, {macro_name})"
            output = output.replace(g["full_match"], replacement)

    return output

# --- COMMAND-LINE INTERFACE --------------------------------------------------

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python remove-duplicated-wmiguid.py input.h output.h")
        sys.exit(1)

    inp, out = sys.argv[1], sys.argv[2]

    with open(inp, "r") as f:
        text = f.read()

    new_text = process_header(text)

    with open(out, "w") as f:
        f.write(new_text)

    print("Done.")
