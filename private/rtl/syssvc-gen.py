#!/usr/bin/env python3

# This file generates both the system service stubs and the wdm service stubs

from __future__ import print_function
from jinja2 import Environment, BaseLoader
import argparse
import re
import sys
import os
import xml.dom.minidom


SVC_GEN_H_TEMPLATE = """#pragma once

typedef enum _{{svc_group_upper}}_SERVICE_NUMBER {
{%- for svc in svc_list %}
    {{svc.enum_tag}},
{%- endfor %}
    NUMBER_OF_{{svc_group_upper}}_SERVICES
} {{svc_group_upper}}_SERVICE_NUMBER;
"""

NTOS_SVC_GEN_H_TEMPLATE = """#pragma once

#include <ntos.h>
{# #}
{%- for svc in svc_list %}
NTSTATUS {{svc.name}}(IN ASYNC_STATE AsyncState,
{{svc.server_param_indent}}IN struct _THREAD *Thread{%- for param in svc.params %},
{{svc.server_param_indent}}{{param.annotation}} {{param.server_decl}}{%- endfor %});
{# #}
{%- endfor %}
"""

SVC_PARAMS_GEN_H_TEMPLATE = """typedef union _{{svc_group_upper}}_SERVICE_PARAMETERS {
{%- for svc in svc_list %}
    struct {
{%- for param in svc.in_params %}
        {{param.server_decl}};
{%- endfor %}
    } {{svc.name}}Params;
{%- endfor %}
} {{svc_group_upper}}_SERVICE_PARAMETERS, *P{{svc_group_upper}}_SERVICE_PARAMETERS;
"""

NTOS_SVC_GEN_C_TEMPLATE = """#include <ntos.h>
{{extra_headers}}

static inline NTSTATUS {{handler_func}}(IN ULONG SvcNum,
                        {{handler_func_indent}}IN PTHREAD Thread,
                        {{handler_func_indent}}IN ULONG ReqMsgLength,
                        {{handler_func_indent}}OUT ULONG *ReplyMsgLength,
                        {{handler_func_indent}}OUT ULONG *MsgBufferEnd)
{
    NTSTATUS Status = STATUS_INVALID_PARAMETER;
    switch (SvcNum) {
{%- for svc in svc_list %}
    case {{svc.enum_tag}}:
    {
        assert(SVC_MSGBUF_SIZE > (0{% for param in svc.out_params %}{% if param.complex_type %} + sizeof({{param.base_type}}){% endif %}{% endfor %}));
        if (ReqMsgLength != {{svc.msglength}}) {
            DbgTrace("Invalid service message length for {{svc_group}} service %d (expect %d got %d)\\n",
                     SvcNum, {{svc.msglength}}, ReqMsgLength);
            break;
        }
{%- for param in svc.in_params %}
{%- if param.is_ptr %}
{%- if param.custom_marshaling %}
        if (!{{param.validate_func}}(Thread->IpcBufferServerAddr, seL4_GetMR({{loop.index-1}}), {% if param.optional %}TRUE{% else %}FALSE{% endif %})) {
            DbgTrace("Invalid argument at position %d (starting from one). Argument is 0x%zx.\\n",
                     {{loop.index}}, seL4_GetMR({{loop.index-1}}));
            break;
        }
        {{param.server_decl}} = {{param.unmarshal_func}}(Thread->IpcBufferServerAddr, seL4_GetMR({{loop.index-1}}));
{%- else %}
        SERVICE_ARGUMENT {{param.name}}ArgBuf;
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
            if (!(KiServiceValidateArgument({{param.name}}ArgBuf.Word)
                  && ({{param.name}}ArgBuf.BufferSize == sizeof({{param.base_type}})))) {
                DbgTrace("Invalid argument at position %d (starting from one). Argument is 0x%zx.\\n",
                         {{loop.index}}, {{param.name}}ArgBuf.Word);
                break;
            }
            {{param.name}} = KiServiceGetArgument(Thread->IpcBufferServerAddr, {{param.name}}ArgBuf.Word);
        }
{%- endif %}
{%- else %}
        {{param.base_type}} {{param.name}} = ({{param.base_type}}) seL4_GetMR({{loop.index-1}});
{%- endif %}
{%- endfor %}
{%- for param in svc.out_params %}
{%- if not param.dir_in %}
        {{param.base_type}} {{param.name}};
{%- endif %}
{%- endfor %}
        DbgTrace("Calling {{svc.name}}\\n");
        KI_DEFINE_INIT_ASYNC_STATE(AsyncState, Thread);
        Status = {{svc.name}}(AsyncState, Thread{% for param in svc.params %}, {% if param.dir_out and not param.dir_in %}&{% endif %}{{param.name}}{% endfor %});
        if (Status == STATUS_ASYNC_PENDING) {
            DbgTrace("{{svc.name}} returned async pending status. Suspending thread %p\\n", Thread);
            RET_ERR_EX(KiServiceSaveReplyCap(Thread), assert(STATUS_NTOS_BUG));
            Thread->SvcNum = SvcNum;
            Thread->WdmSvc = {% if wdmsvc %}TRUE{% else %}FALSE{% endif%};
{%- for param in svc.in_params %}
            Thread->{%- if wdmsvc %}WdmSvcParams{% else %}SysSvcParams{% endif%}.{{svc.name}}Params.{{param.name}} = {{param.name}};
{%- endfor %}
        } else {
            DbgTrace("{{svc.name}} returned status 0x%x. Replying to thread %p\\n", Status, Thread);
{%- for param in svc.out_params %}
{%- if param.dir_in %}
            {{param.base_type}} {{param.name}}Out = *{{param.name}};
{%- endif %}
{%- endfor %}
            ULONG MsgBufOffset = 0;
            *ReplyMsgLength = 1 + {{svc.out_params|length}};
{%- for param in svc.out_params %}
{%- if param.complex_type %}
            SERVICE_ARGUMENT {{param.name}}ArgBufOut;
            RET_ERR_EX(KiServiceMarshalArgument(Thread->IpcBufferServerAddr, &MsgBufOffset, (PVOID) &({{param.name}}{% if param.dir_in %}Out{% endif %}), sizeof({{param.base_type}}), &{{param.name}}ArgBufOut), assert(STATUS_NTOS_BUG));
            seL4_SetMR({{loop.index}}, {{param.name}}ArgBufOut.Word);
{%- else %}
            seL4_SetMR({{loop.index}}, (MWORD) {{param.name}}{%- if param.dir_in %}Out{%- endif %});
{%- endif %}
{%- endfor %}
            *MsgBufferEnd = MsgBufOffset;
        }
        break;
    }
{# #}
{%- endfor %}
    default:
        DbgTrace("Invalid {{svc_group}} service number %d\\n", SvcNum);
        break;
    }
    return Status;
}
{# #}
static inline NTSTATUS {{resume_func}}(IN PTHREAD Thread,
                        {{resume_func_indent}}OUT ULONG *ReplyMsgLength,
                        {{resume_func_indent}}OUT ULONG *MsgBufferEnd)
{
    assert(Thread->WdmSvc == {%- if wdmsvc %}TRUE{% else %}FALSE{% endif%});
    NTSTATUS Status = STATUS_INVALID_PARAMETER;
    ULONG SvcNum = Thread->SvcNum;
    switch (SvcNum) {
{%- for svc in svc_list %}
    case {{svc.enum_tag}}:
    {
{%- for param in svc.in_params %}
        {{param.server_decl}} = Thread->{%- if wdmsvc %}WdmSvcParams{% else %}SysSvcParams{% endif%}.{{svc.name}}Params.{{param.name}};
{%- endfor %}
{%- for param in svc.out_params %}
{%- if not param.dir_in %}
        {{param.base_type}} {{param.name}};
{%- endif %}
{%- endfor %}
        DbgTrace("Resuming thread %p. Calling {{svc.name}} with saved context.\\n", Thread);
        KI_DEFINE_INIT_ASYNC_STATE(AsyncState, Thread);
        Status = {{svc.name}}(AsyncState, Thread{% for param in svc.params %}, {% if param.dir_out and not param.dir_in %}&{% endif %}{{param.name}}{% endfor %});
        if (Status == STATUS_ASYNC_PENDING) {
            DbgTrace("{{svc.name}} returned async pending status. Suspending thread %p\\n", Thread);
        } else {
            DbgTrace("{{svc.name}} returned status 0x%x. Replying to thread %p\\n", Status, Thread);
{%- for param in svc.out_params %}
{%- if param.dir_in %}
            {{param.base_type}} {{param.name}}Out = *{{param.name}};
{%- endif %}
{%- endfor %}
            ULONG MsgBufOffset = 0;
            *ReplyMsgLength = 1 + {{svc.out_params|length}};
{%- for param in svc.out_params %}
{%- if param.complex_type %}
            SERVICE_ARGUMENT {{param.name}}ArgBufOut;
            RET_ERR_EX(KiServiceMarshalArgument(Thread->IpcBufferServerAddr, &MsgBufOffset, (PVOID) &({{param.name}}{% if param.dir_in %}Out{% endif %}), sizeof({{param.base_type}}), &{{param.name}}ArgBufOut), assert(STATUS_NTOS_BUG));
            seL4_SetMR({{loop.index}}, {{param.name}}ArgBufOut.Word);
{%- else %}
            seL4_SetMR({{loop.index}}, (MWORD) {{param.name}}{%- if param.dir_in %}Out{%- endif %});
{%- endif %}
{%- endfor %}
            *MsgBufferEnd = MsgBufOffset;
        }
        break;
    }
{# #}
{%- endfor %}
    default:
        DbgTrace("BUGBUG!! BUGBUG!! Invalid {{svc_group}} service number %d when resuming thread %p.\\n", SvcNum, Thread);
        assert(FALSE);
        break;
    }
    return Status;
}
"""

CLIENT_SVC_GEN_H_TEMPLATE = """#pragma once
{% for svc in svc_list %}
{% if svc.ntapi %}NTAPI {% endif %}NTSTATUS {{svc.name}}({%- for param in svc.params %}{{param.annotation}} {{param.client_decl}}{%- if not loop.last %},
{{svc.client_param_indent}}
{%- endif %}{%- endfor %});
{% endfor %}
"""

CLIENT_SVC_GEN_C_TEMPLATE = """static inline VOID KiDeliverApc(IN MWORD IpcBufferStart,
                                IN MWORD Arg,
                                IN SHORT NumApc)
{
    assert(NumApc > 0);
    APC_OBJECT Apc[MAX_APC_COUNT_PER_DELIVERY];
    memcpy(Apc, KiServiceGetArgument(IpcBufferStart, Arg), NumApc * sizeof(APC_OBJECT));
    for (SHORT i = 0; i < NumApc; i++) {
        assert(Apc[i].ApcRoutine != NULL);
        if (Apc[i].ApcRoutine != NULL) {
            DbgTrace("Delivering APC Routine %p Arguments %p %p %p\\n", Apc->ApcRoutine,
                     Apc->ApcContext[0], Apc->ApcContext[1], Apc->ApcContext[2]);
            (Apc[i].ApcRoutine)(Apc[i].ApcContext[0], Apc[i].ApcContext[1], Apc[i].ApcContext[2]);
        }
    }
}

{% for svc in svc_list %}{% if svc.ntapi %}NTAPI {% endif %}NTSTATUS {{svc.name}}({%- for param in svc.params %}{{param.annotation}} {{param.client_decl}}{%- if not loop.last %},
{{svc.client_param_indent}}
{%- endif %}{%- endfor %})
{
    seL4_MessageInfo_t Request = seL4_MessageInfo_new({{svc.enum_tag}}, 0, 0, {{svc.msglength}});
    ULONG MsgBufOffset = 0;
{%- for param in svc.params %}
{%- if param.is_ptr and not param.optional %}
    if ({{param.name}} == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
{%- endif %}
{%- endfor %}
{%- for param in svc.in_params %}
{%- if param.is_ptr %}
{%- if param.optional %}
    if ({{param.name}} == NULL) {
        seL4_SetMR({{loop.index-1}}, 0);
    } else {
{%- endif %}
{%if param.optional%}    {%endif%}    SERVICE_ARGUMENT {{param.name}}ArgBuf;
{%- if param.custom_marshaling %}
{%if param.optional%}    {%endif%}    RET_ERR({{param.marshal_func}}(&MsgBufOffset, {{param.name}}, &{{param.name}}ArgBuf));
{%- else %}
{%if param.optional%}    {%endif%}    RET_ERR(KiServiceMarshalArgument((ULONG_PTR)(__sel4_ipc_buffer), &MsgBufOffset, {{param.name}}, sizeof({{param.base_type}}), &{{param.name}}ArgBuf));
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
    seL4_MessageInfo_t Reply = seL4_Call({{svc_ipc_cap}}, Request);
    NTSTATUS Status = seL4_GetMR(0);
    if (NT_SUCCESS(Status)) {
        assert(seL4_MessageInfo_get_length(Reply) == (1 + {{svc.out_params|length}}));
        SHORT NumApc = (SHORT)seL4_MessageInfo_get_label(Reply);
        SERVICE_ARGUMENT Arg = { .Word = 0 };
{%- for param in svc.out_params %}
        if ({{param.name}} != NULL) {
{%- if param.complex_type %}
            assert(KiServiceValidateArgument(seL4_GetMR({{loop.index}})));
            *{{param.name}} = *(({{param.base_type}} *)(KiServiceGetArgument((ULONG_PTR)(__sel4_ipc_buffer), seL4_GetMR({{loop.index}}))));
            Arg.Word = seL4_GetMR({{loop.index}});
{%- else %}
            *{{param.name}} = ({{param.base_type}}) seL4_GetMR({{loop.index}});
{%- endif %}
        }
{%- endfor %}
        if (NumApc != 0) {
            BOOLEAN MoreToCome = NumApc < 0;
            if (NumApc < 0) {
                NumApc = -NumApc;
            }
            Arg.BufferStart += Arg.BufferSize;
            Arg.BufferSize = NumApc * sizeof(APC_OBJECT);
            KiDeliverApc((ULONG_PTR)(__sel4_ipc_buffer), Arg.Word, NumApc);
            if (MoreToCome) {
                NtTestAlert();
            }
        }
    }
    return Status;
}
{%- if not loop.last %}
{# #}
{%- endif %}
{% endfor %}
"""

def camel_case_to_upper_snake_case(name):
    result = re.sub('(.)([A-Z][a-z]+)', r'\1_\2', name)
    return re.sub('([a-z0-9])([A-Z])', r'\1_\2', result).upper()

# is_ptr == True indicates that the argument passed into the stub
# function is a pointer to its base type, listed in the syssvc.xml
# as ptr<base_type>. If an input parameter is marked is_ptr it will
# always be passed via the system service message buffer. Output
# parameters are always assumed to be is_ptr and we raise an exception
# if it is not marked as such. The stub function will check the argument
# for an is_ptr parameter for NULL-value. If parameter is not optional
# and user passed a NULL-argument, then stub function returns immediately
# with STATUS_INVALID_PARAMETER, without calling the server.
#
# Since output parameters always have is_ptr == True we use complex_type
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
class ServiceParameter:
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
            raise ValueError("Use AnsiString for PCSTR")
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
            self.unmarshal_func = "KiServiceGetArgument"
        elif param_type == "AnsiString":
            self.custom_marshaling = True
            self.is_ptr = True
            self.server_type = "PCSTR"
            self.server_decl = "PCSTR " + name
            self.client_decl = "PCSTR " + name
            self.marshal_func = "KiMarshalAnsiString"
            self.validate_func = "KiValidateUnicodeString"
            self.unmarshal_func = "KiServiceGetArgument"
        elif param_type == "ObjectAttributes":
            self.custom_marshaling = True
            self.is_ptr = True
            self.server_type = "OB_OBJECT_ATTRIBUTES"
            self.server_decl = "OB_OBJECT_ATTRIBUTES " + name
            self.client_decl = "POBJECT_ATTRIBUTES " + name
            self.marshal_func = "KiMarshalObjectAttributes"
            self.validate_func = "KiValidateObjectAttributes"
            self.unmarshal_func = "KiUnmarshalObjectAttributes"
        elif param_type == "AnsiObjectAttributes":
            self.custom_marshaling = True
            self.is_ptr = True
            self.server_type = "OB_OBJECT_ATTRIBUTES"
            self.server_decl = "OB_OBJECT_ATTRIBUTES " + name
            self.client_decl = "POBJECT_ATTRIBUTES_ANSI " + name
            self.marshal_func = "KiMarshalObjectAttributesA"
            self.validate_func = "KiValidateObjectAttributesA"
            self.unmarshal_func = "KiUnmarshalObjectAttributesA"
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

class Service:
    def __init__(self, name, enum_tag, params, client_only, wdmsvc):
        self.name = name
        self.enum_tag = enum_tag
        self.params = params
        self.client_only = client_only
        self.in_params = [ param for param in params if param.dir_in ]
        self.out_params = [ param for param in params if param.dir_out ]
        self.server_param_indent = " " * (len("NTSTATUS") + len(name) + 2)
        self.msglength = len(params)
        if len(params) == 0 or wdmsvc:
            self.ntapi = False
        else:
            self.ntapi = True
        if self.ntapi:
            self.client_param_indent = " " * (len("NTSTATUS NTAPI") + len(name) + 2)
        else:
            self.client_param_indent = " " * (len("NTSTATUS") + len(name) + 2)

def generate_file(tmplstr, svc_list, out_file, wdmsvc, server_side):
    template = Environment(loader=BaseLoader, trim_blocks=False,
                           lstrip_blocks=False).from_string(tmplstr)
    if wdmsvc:
        svc_group = "Wdm"
        svc_group_upper = "WDM"
        svc_ipc_cap = "KiWdmServiceCap"
        handler_func = "KiHandleWdmService"
        resume_func = "KiResumeWdmService"
        extra_headers = """
#include <wdmsvc.h>
#include "wdmsvc_gen.h"
#include "ntos_wdmsvc_gen.h"

extern __thread seL4_CPtr KiWdmServiceCap;"""
    else:
        svc_group = "System"
        svc_group_upper = "SYSTEM"
        svc_ipc_cap = "KiSystemServiceCap"
        handler_func = "KiHandleSystemService"
        resume_func = "KiResumeSystemService"
        extra_headers = """
extern __thread seL4_CPtr KiSystemServiceCap;"""
    handler_func_indent = " " * len(handler_func)
    resume_func_indent = " " * len(resume_func)
    data = template.render({ 'svc_list': svc_list,
                             'svc_group': svc_group,
                             'svc_group_upper': svc_group_upper,
                             'svc_ipc_cap': svc_ipc_cap,
                             'handler_func': handler_func,
                             'handler_func_indent': handler_func_indent,
                             'resume_func': resume_func,
                             'resume_func_indent': resume_func_indent,
                             'extra_headers': extra_headers,
                             'wdmsvc': wdmsvc
                            })
    out_file.write(data)

def parse_args():
    parser = argparse.ArgumentParser(description="""Generate NTOS service headers and stubs""")
    parser.add_argument('--syssvc_xml', type=argparse.FileType('r'),
                        help='Full path of the syssvc.xml file', required=True)
    parser.add_argument('--wdmsvc_xml', type=argparse.FileType('r'),
                        help='Full path of the wdmsvc.xml file', required=True)
    parser.add_argument('--out_dir', type=str,
                        help='Output directory for the generated files', required=True)

    result = parser.parse_args()

    return result

def parse_svcxml(xml_file, wdmsvc):
    doc = xml.dom.minidom.parse(xml_file)
    svcs = doc.getElementsByTagName("services")[0]
    svc_list = []
    for svc in svcs.getElementsByTagName("svc"):
        name = str(svc.getAttribute("name"))
        enum_tag = camel_case_to_upper_snake_case(name)
        params = []
        ansi_params = []
        has_unicode_string = False
        for param in svc.getElementsByTagName("parameter"):
            annotation = str(param.getAttribute("annotation")).lower()
            param_name = str(param.getAttribute("name"))
            param_type = str(param.getAttribute("type"))
            params.append(ServiceParameter(annotation, param_type, param_name))
            if param_type == "UnicodeString":
                has_unicode_string = True
                ansi_params.append(ServiceParameter(annotation, "AnsiString", param_name))
            elif param_type == "ObjectAttributes":
                has_unicode_string = True
                ansi_params.append(ServiceParameter(annotation, "AnsiObjectAttributes", param_name))
            else:
                ansi_params.append(ServiceParameter(annotation, param_type, param_name))
        svc_list.append(Service(name, enum_tag, params, client_only = False, wdmsvc = wdmsvc))
        if has_unicode_string:
            svc_list.append(Service(name+"A", enum_tag, ansi_params, client_only = True, wdmsvc = wdmsvc))

    # sanity check
    assert len(svc_list) != 0
    return svc_list

# For system services with UnicodeString parameters, we generate an ANSI (UTF-8)
# version such that client can call it without first converting to UTF-16
def generate_client_svc_list(svcs):
    client_svc_list = []
    for svc in svcs:
        has_unicode_string = False
        params = []
        if has_unicode_string:
            client_svc_list.append(Service(svc.name + "A", enum_tag, params))
    return client_svc_list

if __name__ == "__main__":
    args = parse_args()
    syssvc_list = parse_svcxml(args.syssvc_xml, wdmsvc = False)
    server_syssvc_list = [syssvc for syssvc in syssvc_list if not syssvc.client_only]
    wdmsvc_list = parse_svcxml(args.wdmsvc_xml, wdmsvc = True)
    server_wdmsvc_list = [svc for svc in wdmsvc_list if not svc.client_only]

    svc_params_gen_h = open(os.path.join(args.out_dir, "ntos_svc_params_gen.h"), "w")
    generate_file(SVC_PARAMS_GEN_H_TEMPLATE, server_syssvc_list, svc_params_gen_h, wdmsvc = False, server_side = True)
    svc_params_gen_h.write("\n\n")
    generate_file(SVC_PARAMS_GEN_H_TEMPLATE, server_wdmsvc_list, svc_params_gen_h, wdmsvc = True, server_side = True)

    syssvc_gen_h = open(os.path.join(args.out_dir, "syssvc_gen.h"), "w")
    generate_file(SVC_GEN_H_TEMPLATE, server_syssvc_list, syssvc_gen_h, wdmsvc = False, server_side = True)

    ntos_syssvc_gen_h = open(os.path.join(args.out_dir, "ntos_syssvc_gen.h"), "w")
    generate_file(NTOS_SVC_GEN_H_TEMPLATE, server_syssvc_list, ntos_syssvc_gen_h, wdmsvc = False, server_side = True)
    ntos_syssvc_gen_c = open(os.path.join(args.out_dir, "ntos_syssvc_gen.c"), "w")
    generate_file(NTOS_SVC_GEN_C_TEMPLATE, server_syssvc_list, ntos_syssvc_gen_c, wdmsvc = False, server_side = True)

    client_syssvc_list = generate_client_svc_list(syssvc_list)
    ntdll_syssvc_gen_h = open(os.path.join(args.out_dir, "ntdll_syssvc_gen.h"), "w")
    generate_file(CLIENT_SVC_GEN_H_TEMPLATE, syssvc_list, ntdll_syssvc_gen_h, wdmsvc = False, server_side = False)
    ntdll_syssvc_gen_c = open(os.path.join(args.out_dir, "ntdll_syssvc_gen.c"), "w")
    generate_file(CLIENT_SVC_GEN_C_TEMPLATE, syssvc_list, ntdll_syssvc_gen_c, wdmsvc = False, server_side = False)

    wdmsvc_gen_h = open(os.path.join(args.out_dir, "wdmsvc_gen.h"), "w")
    generate_file(SVC_GEN_H_TEMPLATE, server_wdmsvc_list, wdmsvc_gen_h, wdmsvc = True, server_side = True)
    ntos_wdmsvc_gen_h = open(os.path.join(args.out_dir, "ntos_wdmsvc_gen.h"), "w")
    generate_file(NTOS_SVC_GEN_H_TEMPLATE, server_wdmsvc_list, ntos_wdmsvc_gen_h, wdmsvc = True, server_side = True)
    ntos_wdmsvc_gen_c = open(os.path.join(args.out_dir, "ntos_wdmsvc_gen.c"), "w")
    generate_file(NTOS_SVC_GEN_C_TEMPLATE, server_wdmsvc_list, ntos_wdmsvc_gen_c, wdmsvc = True, server_side = True)

    client_wdmsvc_list = generate_client_svc_list(wdmsvc_list)
    wdm_wdmsvc_gen_h = open(os.path.join(args.out_dir, "wdm_wdmsvc_gen.h"), "w")
    generate_file(CLIENT_SVC_GEN_H_TEMPLATE, wdmsvc_list, wdm_wdmsvc_gen_h, wdmsvc = True, server_side = False)
    wdm_wdmsvc_gen_c = open(os.path.join(args.out_dir, "wdm_wdmsvc_gen.c"), "w")
    generate_file(CLIENT_SVC_GEN_C_TEMPLATE, wdmsvc_list, wdm_wdmsvc_gen_c, wdmsvc = True, server_side = False)
