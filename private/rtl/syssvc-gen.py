#!/usr/bin/env python3

from __future__ import print_function
from jinja2 import Environment, BaseLoader
import argparse
import re
import sys
import os
import xml.dom.minidom


SYSSVC_GEN_H_TEMPLATE = """#pragma once

typedef enum _SYSTEM_SERVICE_NUMBER {
    {%- for syssvc in syssvc_list %}
    {{syssvc.enum_tag}},
    {%- endfor %}
    NUMBER_OF_SYSTEM_SERVICES
} SYSTEM_SERVICE_NUMBER;
"""

NTOS_SYSSVC_GEN_H_TEMPLATE = """#pragma once

#include <ntos.h>
{# #}
{%- for syssvc in syssvc_list %}
NTSTATUS {{syssvc.name}}(struct _THREAD *Thread{%- for param in syssvc.params %},
{{syssvc.server_param_indent}}{{param.annotation}} {{param.server_decl}}{%- endfor %});
{# #}
{%- endfor %}
"""

NTOS_SYSSVC_GEN_C_TEMPLATE = """#include <ntos.h>

static inline NTSTATUS KiHandleSystemService(IN ULONG SvcNum,
                                             IN PTHREAD Thread,
                                             IN ULONG ReqMsgLength,
                                             OUT ULONG *ReplyMsgLength)
{
    NTSTATUS Status = STATUS_INVALID_PARAMETER;
    switch (SvcNum) {
{%- for syssvc in syssvc_list %}
    case {{syssvc.enum_tag}}:
    {
        assert(SYSSVC_MESSAGE_BUFFER_SIZE > (0{% for param in syssvc.out_params %}{% if param.complex_type %} + sizeof({{param.base_type}}){% endif %}{% endfor %}));
        if (ReqMsgLength != {{syssvc.msglength}}) {
            DbgTrace("Invalid service message length for service %d (expect %d got %d)\\n",
                     SvcNum, {{syssvc.msglength}}, ReqMsgLength);
            break;
        }
{%- for param in syssvc.in_params %}
{%- if param.is_ptr %}
{%- if param.custom_marshaling %}
        if (!{{param.validate_func}}(Thread->IpcBufferServerAddr, seL4_GetMR({{loop.index-1}}), {% if param.optional %}TRUE{% else %}FALSE{% endif %})) {
            DbgTrace("Invalid argument at position %d (starting from one). Argument is 0x%zx.\\n",
                     {{loop.index}}, seL4_GetMR({{loop.index-1}}));
            break;
        }
        {{param.server_decl}} = {{param.unmarshal_func}}(Thread->IpcBufferServerAddr, seL4_GetMR({{loop.index-1}}));
{%- else %}
        SYSTEM_SERVICE_ARGUMENT {{param.name}}ArgBuf;
        {{param.name}}ArgBuf.Word = seL4_GetMR({{loop.index-1}});
        {{param.server_decl}};
        if ({{param.name}}ArgBuf.Word == 0) {
{%- if param.optional %}
            {{param.name}} = NULL;
{%- else %}
            DbgTrace("Invalid argument at position %d (starting from one). Argument is 0x%zx.\\n",
                     {{loop.index}}, {{param.name}}ArgBuf.Word);
            break;
{%- endif %}
        } else {
            if (!(KiSystemServiceValidateArgument({{param.name}}ArgBuf.Word)
                  && ({{param.name}}ArgBuf.BufferSize == sizeof({{param.base_type}})))) {
                DbgTrace("Invalid argument at position %d (starting from one). Argument is 0x%zx.\\n",
                         {{loop.index}}, {{param.name}}ArgBuf.Word);
                break;
            }
            {{param.name}} = KiSystemServiceGetArgument(Thread->IpcBufferServerAddr, {{param.name}}ArgBuf.Word);
        }
{%- endif %}
{%- else %}
        {{param.base_type}} {{param.name}} = ({{param.base_type}}) seL4_GetMR({{loop.index-1}});
{%- endif %}
{%- endfor %}
{%- for param in syssvc.out_params %}
{%- if not param.dir_in %}
        {{param.base_type}} {{param.name}};
{%- endif %}
{%- endfor %}
        DbgTrace("Calling {{syssvc.name}}\\n");
        Status = {{syssvc.name}}(Thread{% for param in syssvc.params %}, {% if param.dir_out and not param.dir_in %}&{% endif %}{{param.name}}{% endfor %});
{%- for param in syssvc.out_params %}
{%- if param.dir_in %}
        {{param.base_type}} {{param.name}}Out = *{{param.name}};
{%- endif %}
{%- endfor %}
        ULONG MsgBufOffset = 0;
        *ReplyMsgLength = 1 + {{syssvc.out_params|length}};
{%- for param in syssvc.out_params %}
{%- if param.complex_type %}
        SYSTEM_SERVICE_ARGUMENT {{param.name}}ArgBufOut;
RET_ERR_EX(KiSystemServiceMarshalArgument(Thread->IpcBufferServerAddr, &MsgBufOffset, (PVOID) &({{param.name}}{% if param.dir_in %}Out{% endif %}), sizeof({{param.base_type}}), &{{param.name}}ArgBufOut), assert(STATUS_NTOS_BUG));
        seL4_SetMR({{loop.index}}, {{param.name}}ArgBufOut.Word);
{%- else %}
        seL4_SetMR({{loop.index}}, (MWORD) {{param.name}});
{%- endif %}
{%- endfor %}
        break;
    }
{# #}
{%- endfor %}
    default:
        DbgTrace("Invalid system service number %d\\n", SvcNum);
        break;
    }
    return Status;
}
{# #}
"""

NTDLL_SYSSVC_GEN_H_TEMPLATE = """#pragma once
{% for syssvc in syssvc_list %}
{% if syssvc.params != [] %}NTAPI {% endif %}NTSTATUS {{syssvc.name}}({%- for param in syssvc.params %}{{param.annotation}} {{param.client_decl}}{%- if not loop.last %},
{{syssvc.client_param_indent}}
{%- endif %}{%- endfor %});
{% endfor %}
"""

NTDLL_SYSSVC_GEN_C_TEMPLATE = """#include <ntdll.h>
{% for syssvc in syssvc_list %}
{% if syssvc.params != [] %}NTAPI {% endif %}NTSTATUS {{syssvc.name}}({%- for param in syssvc.params %}{{param.annotation}} {{param.client_decl}}{%- if not loop.last %},
{{syssvc.client_param_indent}}
{%- endif %}{%- endfor %})
{
    seL4_MessageInfo_t Request = seL4_MessageInfo_new({{syssvc.svcnum}}, 0, 0, {{syssvc.msglength}});
    ULONG MsgBufOffset = 0;
{%- for param in syssvc.params %}
{%- if param.is_ptr and not param.optional %}
    if ({{param.name}} == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
{%- endif %}
{%- endfor %}
{%- for param in syssvc.in_params %}
{%- if param.is_ptr %}
{%- if param.optional %}
    if ({{param.name}} == NULL) {
        seL4_SetMR({{loop.index-1}}, 0);
    } else {
{%- endif %}
{%if param.optional%}    {%endif%}    SYSTEM_SERVICE_ARGUMENT {{param.name}}ArgBuf;
{%- if param.custom_marshaling %}
{%if param.optional%}    {%endif%}    RET_ERR({{param.marshal_func}}(&MsgBufOffset, {{param.name}}, &{{param.name}}ArgBuf));
{%- else %}
{%if param.optional%}    {%endif%}    RET_ERR(KiSystemServiceMarshalArgument(SYSSVC_MESSAGE_BUFFER_START, &MsgBufOffset, {{param.name}}, sizeof({{param.base_type}}), &{{param.name}}ArgBuf));
{%- endif %}
{%if param.optional%}    {%endif%}    seL4_SetMR({{loop.index-1}}, (MWORD) {{param.name}}ArgBuf.Word);
{%- if param.optional %}
    }
{%- endif %}
{%- else %}
{%- if param.custom_marshaling %}
    seL4_SetMR({{loop.index-1}}, {{param.marshal_func}}({{param.name}}));
{%- else %}
    seL4_SetMR({{loop.index-1}}, (MWORD) {{param.name}});
{%- endif %}
{%- endif %}
{%- endfor %}
    seL4_MessageInfo_t Reply = seL4_Call(SYSSVC_IPC_CAP, Request);
    NTSTATUS Status = seL4_GetMR(0);
    if (NT_SUCCESS(Status)) {
        assert(seL4_MessageInfo_get_length(Reply) == (1 + {{syssvc.out_params|length}}));
{%- for param in syssvc.out_params %}
        if ({{param.name}} != NULL) {
{%- if param.complex_type %}
            assert(KiSystemServiceValidateArgument(seL4_GetMR({{loop.index}})));
            *{{param.name}} = *(({{param.base_type}} *)(KiSystemServiceGetArgument(SYSSVC_MESSAGE_BUFFER_START, seL4_GetMR({{loop.index}}))));
{%- else %}
            *{{param.name}} = ({{param.base_type}}) seL4_GetMR({{loop.index}});
{%- endif %}
        }
{%- endfor %}
    }
    return Status;
}
{% endfor %}
{# #}
"""

def camel_case_to_upper_snake_case(name):
    result = re.sub('(.)([A-Z][a-z]+)', r'\1_\2', name)
    return re.sub('([a-z0-9])([A-Z])', r'\1_\2', result).upper()

# is_ptr == True indicates that the argument passed into the stub
# function is a pointer to its base type, listed in the syssvc.xml
# as ptr<base_type>. If an input parameter is marked is_ptr it will
# always be passed via the system service message buffer. Output
# parameters are always assumed to be is_ptr and will raise an exception
# if it is not marked as such. The stub function will check the argument
# for an is_ptr parameter for NULL-value. If parameter is not optional
# and user passed a NULL-argument, then stub function returns immediately
# with STATUS_INVALID_PARAMETER, without calling the server.
#
# Since output parameters alwasy have is_ptr == True we use complex_type
# == True to distinguish the case where it needs to be passed via the
# system service message buffer. If an output parameter is not marked
# complex (the default) it will be passed via the message register (in
# this case the parameter cannot exceed the machine word size).
#
# For pointer types the base_type will be the type it refers to
# (ie. if function signature is NTSTATUS fcn(PULONG Arg) the base_type
# for parameter Arg will be ULONG).
#
# If parameter is marked custom_marshaling, the custom marshaling
# function will be called when passing the argument. For pointer
# types (is_ptr == True), the marshaling function will copy the argument
# into the system service message buffer. For non-pointer types,
# the marshaling function will convert the type into MWORD.
class SystemServiceParameter:
    def __init__(self, annotation, param_type, name):
        annotations = []
        self.optional = False
        self.complex_type = False
        self.dir_in = False
        self.dir_out = False
        self.is_ptr = False
        if "in" in annotation:
            self.dir_in = True
            annotations.append("IN")
        if "out" in annotation:
            self.dir_out = True
            self.is_ptr = True
            annotations.append("OUT")
        if "opt" in annotation:
            self.optional = True
            annotations.append("OPTIONAL")
        if "complex" in annotation:
            self.complex_type = True
        if not self.dir_in and not self.dir_out:
            raise ValueError("Parameter " + name + " must have directional annotations (either IN or OUT)")
        self.annotation = " ".join(annotations)
        if "::" in param_type:
            self.is_ptr = True
            self.base_type = re.search('::(.*)', param_type).group(1)
        else:
            self.is_ptr = False
            self.base_type = param_type
        self.name = name
        if "UNICODE_STRING" in param_type.upper():
            raise ValueError("Use UnicodeString for PUNICODE_STRING")
        if "PCSTR" in param_type.upper():
            raise ValueError("Use UnicodeString for PCSTR")
        if "OBJECT_ATTRIBUTES" in param_type.upper():
            raise ValueError("Use ObjectAttributes for OBJECT_ATTRIBUTES")
        if param_type == "UnicodeString":
            self.custom_marshaling = True
            self.is_ptr = True
            self.server_type = "PCSTR"
            self.server_decl = "PCSTR " + name
            self.client_decl = "PUNICODE_STRING " + name
            self.marshal_func = "KiMarshalUnicodeString"
            self.validate_func = "KiValidateUnicodeString"
            self.unmarshal_func = "KiSystemServiceGetArgument"
        elif param_type == "ObjectAttributes":
            self.custom_marshaling = True
            self.is_ptr = True
            self.server_type = "OB_OBJECT_ATTRIBUTES"
            self.server_decl = "OB_OBJECT_ATTRIBUTES " + name
            self.client_decl = "POBJECT_ATTRIBUTES " + name
            self.marshal_func = "KiMarshalObjectAttributes"
            self.validate_func = "KiValidateObjectAttributes"
            self.unmarshal_func = "KiUnmarshalObjectAttributes"
        else:
            self.custom_marshaling = False
            if self.dir_out:
                self.server_type = self.base_type + " *"
                self.server_decl = self.base_type + " *" + name
                self.client_decl = self.base_type + " *" + name
            elif self.is_ptr:
                self.server_type = "P" + self.base_type
                self.server_decl = "P" + self.base_type + " " + name
                self.client_decl = "P" + self.base_type + " " + name
            else:
                self.server_decl = param_type + " " + name
                self.client_decl = param_type + " " + name
        if self.optional and not self.is_ptr:
            raise ValueError("Parameter " + name + " must be marked ptr because it is optional")
        if self.dir_out and not self.is_ptr:
            raise ValueError("Parameter " + name + " must be marked ptr because it is an output parameter")
        if self.dir_out and self.custom_marshaling:
            raise ValueError("Parameter " + name + ": custom marshaling for output parameter is not yet implemented")

class SystemService:
    def __init__(self, svcnum, name, params):
        self.svcnum = svcnum
        self.name = name
        self.enum_tag = SystemService.name_to_enum_tag(name)
        self.params = params
        self.in_params = [ param for param in params if param.dir_in ]
        self.out_params = [ param for param in params if param.dir_out ]
        self.server_param_indent = " " * (len("NTSTATUS") + len(name) + 2)
        self.client_param_indent = " " * (len("NTSTATUS NTAPI") + len(name) + 2)
        self.msglength = len(params)

    @staticmethod
    def name_to_enum_tag(name):
        return camel_case_to_upper_snake_case(name)

def generate_file(tmplstr, syssvc_list, out_file, server_side):
    template = Environment(loader=BaseLoader, trim_blocks=False,
                           lstrip_blocks=False).from_string(tmplstr)
    data = template.render({ 'syssvc_list': syssvc_list })
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
            annotation = str(param.getAttribute("annotation")).lower()
            param_name = str(param.getAttribute("name"))
            param_type = str(param.getAttribute("type"))
            params.append(SystemServiceParameter(annotation, param_type, param_name))
        syssvc_list.append(SystemService(svcnum, name, params))
        svcnum += 1

    # sanity check
    assert len(syssvc_list) != 0
    return syssvc_list

if __name__ == "__main__":
    args = parse_args()
    syssvc_list = parse_syssvc_xml(args.syssvc_xml)
    syssvc_gen_h = open(os.path.join(args.out_dir, "syssvc_gen.h"), "w")
    generate_file(SYSSVC_GEN_H_TEMPLATE, syssvc_list, syssvc_gen_h, server_side = True)
    ntos_syssvc_gen_h = open(os.path.join(args.out_dir, "ntos_syssvc_gen.h"), "w")
    generate_file(NTOS_SYSSVC_GEN_H_TEMPLATE, syssvc_list, ntos_syssvc_gen_h, server_side = True)
    ntos_syssvc_gen_c = open(os.path.join(args.out_dir, "ntos_syssvc_gen.c"), "w")
    generate_file(NTOS_SYSSVC_GEN_C_TEMPLATE, syssvc_list, ntos_syssvc_gen_c, server_side = True)
    ntdll_syssvc_gen_h = open(os.path.join(args.out_dir, "ntdll_syssvc_gen.h"), "w")
    generate_file(NTDLL_SYSSVC_GEN_H_TEMPLATE, syssvc_list, ntdll_syssvc_gen_h, server_side = False)
    ntdll_syssvc_gen_c = open(os.path.join(args.out_dir, "ntdll_syssvc_gen.c"), "w")
    generate_file(NTDLL_SYSSVC_GEN_C_TEMPLATE, syssvc_list, ntdll_syssvc_gen_c, server_side = False)
