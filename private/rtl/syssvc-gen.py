#!/usr/bin/env python3

from __future__ import print_function
from jinja2 import Environment, BaseLoader
import argparse
import re
import sys
import os
import xml.dom.minidom


SYSSVC_GEN_H_TEMPLATE = """#ifndef SYSSVC_GEN_H
#define SYSSVC_GEN_H

typedef enum _SYSTEM_SERVICE_NUMBER {
    {%- for syssvc in syssvc_list %}
    {{syssvc.enum_tag}},
    {%- endfor %}
    NUMBER_OF_SYSTEM_SERVICES
} SYSTEM_SERVICE_NUMBER;

#endif  /* SYSSVC_GEN_H */
{# #}
"""

NTOS_SYSSVC_GEN_H_TEMPLATE = """#pragma once
{# #}
{%- for syssvc in syssvc_list %}
NTSTATUS Sys{{syssvc.name}}(struct _THREAD *Thread,
{{syssvc.param_indent}}{%- for param in syssvc.params %}{{param.direction}} {{param.server_type}} {{param.name}}{%- if not loop.last %},
{{syssvc.param_indent}}
{%- endif %}{%- endfor %});
{# #}
{%- endfor %}
"""

NTOS_SYSSVC_GEN_C_TEMPLATE = """switch (SvcNum) {
{%- for syssvc in syssvc_list %}
case {{syssvc.enum_tag}}:
    {
        if (SvcMsgLength != {{syssvc.msglength}}) {
            DbgTrace("Invalid service message length for service %d (expect %d got %d)\\n",
                     SvcNum, {{syssvc.msglength}}, SvcMsgLength);
            goto ret;
        }
{%- for param in syssvc.params %}
{%- if param.needs_marshaling %}
        if (!{{param.validate_func}}(Thread, seL4_GetMR({{loop.index-1}}))) {
            DbgTrace("Invalid argument at position %d (starting from one). Argument is 0x%zx.\\n",
                     {{loop.index}}, seL4_GetMR({{loop.index-1}}));
            goto ret;
        }
        {{param.server_type}} {{param.name}} = ({{param.server_type}}) KiSystemServiceGetArgument(Thread, seL4_GetMR({{loop.index-1}}));
{%- else %}
        {{param.server_type}} {{param.name}} = ({{param.server_type}}) seL4_GetMR({{loop.index-1}});
{%- endif %}
{%- endfor %}
        DbgTrace("Calling Sys{{syssvc.name}}\\n");
        Status = Sys{{syssvc.name}}(Thread, {%- for param in syssvc.params %}{{param.name}}{% if not loop.last %}, {% endif %}{%- endfor %});
    }
    break;
{# #}
{%- endfor %}
default:
    DbgTrace("Invalid system service number %d\\n", SvcNum);
    break;
}
{# #}
"""

NTDLL_SYSSVC_GEN_H_TEMPLATE = """#ifndef _NTDLL_SYSSVC_GEN_H
#define _NTDLL_SYSSVC_GEN_H
{# #}
{%- for syssvc in syssvc_list %}NTSTATUS NTAPI {{syssvc.name}}({%- for param in syssvc.params %}{{param.direction}} {{param.client_type}} {{param.name}}{%- if not loop.last %},
{{syssvc.param_indent}}
{%- endif %}{%- endfor %});
{# #}
{# #}
{%- endfor %}
{# #}
#endif  /* _NTDLL_SYSSVC_GEN_H */
"""

NTDLL_SYSSVC_GEN_C_TEMPLATE = """{%- for syssvc in syssvc_list %}NTSTATUS NTAPI {{syssvc.name}}({%- for param in syssvc.params %}{{param.direction}} {{param.client_type}} {{param.name}}{%- if not loop.last %},
{{syssvc.param_indent}}
{%- endif %}{%- endfor %})
{
    seL4_MessageInfo_t Request = seL4_MessageInfo_new({{syssvc.svcnum}}, 0, 0, {{syssvc.msglength}});
    ULONG MsgBufOffset = 0;
{%- for param in syssvc.params %}
{%- if param.needs_marshaling %}
    SYSTEM_SERVICE_ARGUMENT_BUFFER {{param.name}}ArgBuf;
    RET_ERR({{param.marshal_func}}(&MsgBufOffset, {{param.name}}, &{{param.name}}ArgBuf));
    seL4_SetMR({{loop.index-1}}, (MWORD) {{param.name}}ArgBuf.Word);
{%- else %}
    seL4_SetMR({{loop.index-1}}, (MWORD) {{param.name}});
{%- endif %}
{%- endfor %}
    seL4_MessageInfo_t Reply = seL4_Call(SYSSVC_IPC_CAP, Request);
    assert(seL4_MessageInfo_get_length(Reply) == 1);
    return seL4_GetMR(0);
}
{%- if not loop.last %}
{# #}
{# #}
{%- endif %}
{%- endfor %}
{# #}
"""

class SystemServiceParameter:
    def __init__(self, direction, param_type, name):
        if direction == "in":
            self.direction = "IN"
        elif direction == "out":
            self.direction = "OUT"
        elif direction == "in_opt":
            self.direction = "IN OPTIONAL"
        elif direction == "out_opt":
            self.direction = "OUT OPTIONAL"
        else:
            raise ValueError("Invalid parameter direction")
        self.param_type = param_type
        self.name = name
        if "UNICODE_STRING" in param_type.upper():
            raise ValueError("Use UnicodeString for PUNICODE_STRING")
        if "PCSTR" in param_type.upper():
            raise ValueError("Use UnicodeString for PCSTR")
        if param_type == "UnicodeString":
            self.needs_marshaling = True
            self.server_type = "PCSTR"
            self.client_type = "PUNICODE_STRING"
            self.marshal_func = "KiMarshalUnicodeString"
            self.validate_func = "KiSystemServiceValidateUnicodeString"
        else:
            self.needs_marshaling = False
            self.server_type = param_type
            self.client_type = param_type

class SystemService:
    def __init__(self, svcnum, name, params):
        self.svcnum = svcnum
        self.name = name
        self.enum_tag = SystemService.name_to_enum_tag(name)
        self.params = params
        self.param_indent = " " * (len("NTSTATUS") + len(name) + 2)
        self.msglength = len(params)

    @staticmethod
    def name_to_enum_tag(name):
        enum_tag = re.sub('(.)([A-Z][a-z]+)', r'\1_\2', name)
        return re.sub('([a-z0-9])([A-Z])', r'\1_\2', enum_tag).upper()


def generate_file(tmplstr, syssvc_list, out_file):
    template = Environment(loader=BaseLoader, trim_blocks=False,
                           lstrip_blocks=False).from_string(tmplstr)
    data = template.render({'syssvc_list': syssvc_list})
    out_file.write(data)

def parse_args():
    parser = argparse.ArgumentParser(description="""Generate NTOS system service headers and stubs""")
    parser.add_argument('--syssvc_xml', type=argparse.FileType('r'),
                        help='Full path of the syssvc.xml file', required=True)
    parser.add_argument('--out_dir', type=str,
                        help='Output directory for the generated files', required=True)

    result = parser.parse_args()

    return result

def parse_syssvc_xml(xml_file):
    # first check if the file is valid xml
    try:
        doc = xml.dom.minidom.parse(xml_file)
    except:
        print("Error: invalid xml file.", file=sys.stderr)
        sys.exit(-1)

    syssvcs = doc.getElementsByTagName("system-services")[0]
    syssvc_list = []
    svcnum = 0
    for syssvc in syssvcs.getElementsByTagName("syssvc"):
        name = str(syssvc.getAttribute("name"))
        params = []
        for param in syssvc.getElementsByTagName("parameter"):
            param_direction = str(param.getAttribute("direction"))
            param_name = str(param.getAttribute("name"))
            param_type = str(param.getAttribute("type"))
            params.append(SystemServiceParameter(param_direction, param_type, param_name))
        syssvc_list.append(SystemService(svcnum, name, params))
        svcnum += 1

    # sanity check
    assert len(syssvc_list) != 0
    return syssvc_list

if __name__ == "__main__":
    args = parse_args()
    syssvc_list = parse_syssvc_xml(args.syssvc_xml)
    syssvc_gen_h = open(os.path.join(args.out_dir, "syssvc_gen.h"), "w")
    generate_file(SYSSVC_GEN_H_TEMPLATE, syssvc_list, syssvc_gen_h)
    ntos_syssvc_gen_h = open(os.path.join(args.out_dir, "ntos_syssvc_gen.h"), "w")
    generate_file(NTOS_SYSSVC_GEN_H_TEMPLATE, syssvc_list, ntos_syssvc_gen_h)
    ntos_syssvc_gen_c = open(os.path.join(args.out_dir, "ntos_syssvc_gen.c"), "w")
    generate_file(NTOS_SYSSVC_GEN_C_TEMPLATE, syssvc_list, ntos_syssvc_gen_c)
    ntdll_syssvc_gen_h = open(os.path.join(args.out_dir, "ntdll_syssvc_gen.h"), "w")
    generate_file(NTDLL_SYSSVC_GEN_H_TEMPLATE, syssvc_list, ntdll_syssvc_gen_h)
    ntdll_syssvc_gen_c = open(os.path.join(args.out_dir, "ntdll_syssvc_gen.c"), "w")
    generate_file(NTDLL_SYSSVC_GEN_C_TEMPLATE, syssvc_list, ntdll_syssvc_gen_c)
