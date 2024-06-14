#!/usr/bin/env python3

# This file generates the stub routines for both the system services and
# the wdm services. The information needed to generate the stub routines
# are in syssvc.xml.
#
# PARAMETER MARSHALING
#
# When the client invokes a system service, the stub routine marshals
# (ie. copies) the services parameters passed in by the client to the
# server side. There are two strategies for parameter passing: for simple
# non-pointer types that can fit into a single machine word (or pointers
# that we simply want to pass to the server verbatim), we pass them via
# the seL4 message registers (via seL4_SetMR and seL4_GetMR). For pointer
# types, or for types that do not fit into a single machine word, we
# marshal them via the system service message buffer. For some types,
# this parameter marshaling can involve possibly converting the data
# first (such as converting from UTF-16 to UTF-8 for UNICODE_STRING).
#
# In the latter case (pointer types), there are basically three sub-cases
# that we need to handle. The first is marshaling pointers to plain old
# data, such as a struct or a union (or simply an integer). These types
# can easily fit into the system service message buffer (typically 3K
# in size, although this is adjustable). Examples of these types are
#
#     IN OPTIONAL PCONTEXT Context,
#
# or
#
#     OUT PULONG Integer,
#
# or
#
#     IN OUT PPVOID BaseAddress.
#
# What simplifies this case is that the size of the data that need to be
# copied to and from the server is fixed and known (given by the sizeof
# operator). In this case we will always pass the data via the service
# message buffer, and simply pass the offset of the data in the service
# message buffer to the server via seL4 message registers. Buffer space
# for each non-NULL parameter is allocated in the order in which they
# appear in the parameter declarations of the system service. More
# specifically, for the following exemplar system service
#
#    NTSTATUS SystemService(IN OPTIONAL PCONTEXT Context,
#                           OUT PULONG Integer,
#                           IN OUT PPVOID BaseAddress);
#
# assuming Context is not NULL we allocate the following
#
#    |---------------------------------|
#    |     CONTEXT     | ULONG | PVOID |
#    |---------------------------------|
#    ^
#    Start of the service message buffer (this follows the
#    seL4 IPC buffer of the thread)
#
# If on the other hand the Context pointer is NULL, only the following
# will be allocated
#
#    |---------------|
#    | ULONG | PVOID |
#    |---------------|
#    ^
#    Start of the service message buffer
#
# For input parameters (that are not NULL), the user data are copied into
# the buffer before calling the server. For output parameters the buffer
# data returned by the server are copied back to the user-provided buffer.
# Server can read from and write into the service message buffer of a
# thread directly, which for small data (<3K) is faster than having to map
# client pages into server address space first.
#
# The second sub-case of pointer type marshaling is a pointer to types
# such as a UNICODE_STRING, or types that include a UNICODE_STRING,
# such as an OBJECT_ATTRIBUTE. Marshaling these parameters involves
# invoking a conversion function first (such as converting a UTF-16
# string into NUL-terminated UTF-8) and then copying them into the
# service message buffer (in practice this is done in a single step,
# using the function RtlUnicodeToUTF8). Since we uses a single 4K page
# for the seL4 IPC buffer plus service message buffer this implies that
# in practice the PATH strings or other object names are limited to
# around 3000 UTF-8 characters, give or take (depending on if the object
# name is mostly English or if it has more East Asian characters). This
# should not pose much of a problem since Windows until recently (Windows
# 10) does not allow for path strings longer than 260 UCS-2 characters.
# If this becomes problematic we can always increase the service message
# buffer size (8K ought to be enough for everybody).
#
# The third sub-case is when the pointer points to a buffer whose size
# is specified by another integer parameter, and possibly by a third
# parameter specifying the buffer type. Examples of the latter include
# the NtSetValueKey service. For this type of buffers how much we need
# to allocate is determined by the buffer size and possibly the buffer
# type. Since these types of buffers are used for services such as
# NtReadFile and NtWriteFile, their size may well exceed the service
# message buffer size. The strategy we adopt here is that we check the
# size first, and if it fits into the service message buffer, we pass
# them via the service message buffer (ie. copy the user data into the
# service message buffer and tell the server to look there). If on the
# other hand the data size exceeds the service message buffer, we will
# instead pass the user buffer pointer directly to the server. The
# server is then responsible for mapping the user buffer into server
# address space (or directly into a driver address space).
#
# In order to handle these different cases, this script defines what we
# call a BaseMarshaller class, and have different parameter marshalling
# strategies inherit from this base class. The jinja templates defined
# below have various places where the parameter marshaller can hook into
# and inject their custom marshalling code as they see fit. These places
# include the point prior to the client stub functions calling the server
# and after it has called the server, as well as the point where the
# server retrieves the client parameters and after the server has
# completed the service and is about to reply to the client. This scheme
# allows for maximal flexibility while minimizing boilerplate code.

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
NTSTATUS {{svc.server_name}}(IN ASYNC_STATE AsyncState,
{{svc.server_param_indent}}IN struct _THREAD *Thread{%- for param in svc.params %},
{{svc.server_param_indent}}{{param.annotations}} {{param.server_decl}}{%- endfor %});
{# #}
{%- endfor %}
"""

SVC_PARAMS_GEN_H_TEMPLATE = """typedef union _SAVED_SERVICE_PARAMETERS {
{%- for svc in svc_list %}
    struct {
{%- for param in svc.params %}
        {{param.server_decl}};
{%- endfor %}
    } {{svc.server_name}}Params;
{%- if svc.has_marshaler_state %}
    struct {
{%- for param in svc.params %}
{%- if param.marshaler_state_decl %}
        {{param.marshaler_state_decl}};
{%- endif %}
{%- endfor %}
    } {{svc.server_name}}MarshalerState;
{%- endif %}
{%- endfor %}
} SAVED_SERVICE_PARAMETERS, *PSAVED_SERVICE_PARAMETERS;
"""

NTOS_SVC_GEN_C_TEMPLATE = """#include <ntos.h>
{{extra_headers}}

static inline NTSTATUS {{handler_func}}(IN ULONG SvcNum,
                        {{handler_func_indent}}IN PTHREAD Thread,
                        {{handler_func_indent}}IN ULONG ReqMsgLength,
                        {{handler_func_indent}}OUT ULONG *pMsgBufferEnd,
                        {{handler_func_indent}}OUT BOOLEAN *ReplyCapSaved)
{
    *ReplyCapSaved = FALSE;
    NTSTATUS Status = STATUS_INVALID_PARAMETER;
    switch (SvcNum) {
{%- for svc in svc_list %}
    case {{svc.enum_tag}}:
    {
        if (ReqMsgLength != {{svc.msglength}}) {
            DbgTrace("Invalid service message length for {{svc_group}} service %d (expect %d got %d)\\n",
                     SvcNum, {{svc.msglength}}, ReqMsgLength);
            break;
        }
        ULONG MsgBufferEnd = seL4_GetMR({{svc.msglength-1}});
        if (MsgBufferEnd > SVC_MSGBUF_SIZE) {
            DbgTrace("{{svc.server_name}}: Invalid message size %d\\n", MsgBufferEnd);
            break;
        }
        *pMsgBufferEnd = MsgBufferEnd;
{%- for param in svc.params %}
{%- if param.server_pre_marshaling %}
        {{param.server_pre_marshaling|indent(8, False)}}
{%- endif %}
{%- endfor %}
{%- for param in svc.params %}
{%- if param.server_marshaling %}
        {{param.server_marshaling|indent(8, False)}}
{%- endif %}
{%- endfor %}
        Status = KiServiceSaveReplyCap(Thread);
        if (!NT_SUCCESS(Status)) {
            /* This shouldn't happen, but if it did, something is seriously wrong. */
            assert(FALSE);
            goto ServerPostMarshaling_{{svc.server_name}};
        }
        *ReplyCapSaved = TRUE;
        DbgTrace("Calling {{svc.server_name}}\\n");
        KI_DEFINE_INIT_ASYNC_STATE(AsyncState, Thread);
        Status = {{svc.server_name}}(AsyncState, Thread{% for param in svc.params %}, {{param.name}}{% endfor %});
        if (Status == STATUS_ASYNC_PENDING) {
            DbgTrace("{{svc.server_name}} returned async pending status. Suspending thread %p\\n", Thread);
            Thread->SvcNum = SvcNum;
            Thread->WdmSvc = {% if wdmsvc %}TRUE{% else %}FALSE{% endif%};
            Thread->MsgBufferEnd = MsgBufferEnd;
{%- for param in svc.params %}
            Thread->SavedParams.{{svc.server_name}}Params.{{param.name}} = {{param.name}};
{%- endfor %}
        } else {
ServerPostMarshaling_{{svc.server_name}}:
            DbgTrace("{{svc.server_name}} returned status 0x%x. %s to thread %p\\n", Status, Status == STATUS_NTOS_NO_REPLY ? "Not replying" : "Replying", Thread);
{%- for param in svc.params %}
{%- if param.server_post_marshaling %}
            {{param.server_post_marshaling|indent(12, False)}}
{%- endif %}
{%- endfor %}
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
static inline NTSTATUS {{resume_func}}(IN PTHREAD Thread)
{
    assert(Thread->WdmSvc == {%- if wdmsvc %}TRUE{% else %}FALSE{% endif%});
    NTSTATUS Status = STATUS_INVALID_PARAMETER;
    ULONG SvcNum = Thread->SvcNum;
    switch (SvcNum) {
{%- for svc in svc_list %}
    case {{svc.enum_tag}}:
    {
{%- for param in svc.params %}
        {{param.server_decl}} = Thread->SavedParams.{{svc.server_name}}Params.{{param.name}};
{%- endfor %}
        DbgTrace("Resuming thread %p. Calling {{svc.server_name}} with saved context.\\n", Thread);
        KI_DEFINE_INIT_ASYNC_STATE(AsyncState, Thread);
        Status = {{svc.server_name}}(AsyncState, Thread{% for param in svc.params %}, {{param.name}}{% endfor %});
        if (Status == STATUS_ASYNC_PENDING) {
            DbgTrace("{{svc.server_name}} returned async pending status. Suspending thread %p\\n", Thread);
        } else {
            DbgTrace("{{svc.server_name}} returned status 0x%x. %s to thread %p\\n", Status, Status == STATUS_NTOS_NO_REPLY ? "Not replying" : "Replying", Thread);
{%- for param in svc.params %}
{%- if param.server_post_marshaling %}
            {{param.server_post_marshaling|indent(12, False)}}
{%- endif %}
{%- endfor %}
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
{% if svc.ntapi %}NTAPI {% endif %}NTSTATUS {{svc.client_name}}({%- for param in svc.params %}{{param.annotations}} {{param.client_decl}}{%- if not loop.last %},
{{svc.client_param_indent}}
{%- endif %}{%- endfor %});
{% endfor %}
"""

CLIENT_SVC_GEN_C_TEMPLATE = """
{% for svc in svc_list %}{% if svc.ntapi %}NTAPI {% endif %}NTSTATUS {{svc.client_name}}({%- for param in svc.params %}{{param.annotations}} {{param.client_decl}}{%- if not loop.last %},
{{svc.client_param_indent}}
{%- endif %}{%- endfor %})
{
{%- for param in svc.params %}
{%- if param.check_null %}
    if ({{param.name}} == NULL) {
        return STATUS_INVALID_PARAMETER_{{param.idx+1}};
    }
{%- endif %}
{%- endfor %}
    seL4_MessageInfo_t Request = seL4_MessageInfo_new({{svc.enum_tag}}, 0, 0, {{svc.msglength}});
    NTSTATUS Status = STATUS_SUCCESS;
    ULONG MsgBufOffset = 0;
{%- for param in svc.params %}
{%- if param.client_pre_marshaling %}
    {{param.client_pre_marshaling|indent(4, False)}}
{%- endif %}
{%- endfor %}
{%- for param in svc.params %}
{%- if param.client_marshaling %}
    {{param.client_marshaling|indent(4, False)}}
    MsgBufOffset = ALIGN_UP_BY(MsgBufOffset, SVC_MSGBUF_ALIGN);
{%- endif %}
{%- endfor %}
{%- for param in svc.params %}
    seL4_SetMR({{loop.index-1}}, {{param.client_marshaled_param}});
{%- endfor %}
    seL4_SetMR({{svc.msglength-1}}, MsgBufOffset);
    UNUSED seL4_MessageInfo_t Reply = seL4_Call({{svc_ipc_cap}}, Request);
    assert(seL4_MessageInfo_get_length(Reply) == 3);
    Status = seL4_GetMR(0);
    if (!NT_SUCCESS(Status) && Status != STATUS_BUFFER_OVERFLOW && Status != STATUS_BUFFER_TOO_SMALL) {
        goto ClientPostMarshaling;
    }
    ULONG NumApc = seL4_GetMR(1);
    BOOLEAN MoreToCome = seL4_GetMR(2);
{%- for param in svc.params %}
{%- if param.dir_out and param.client_unmarshaling %}
    if ({{param.name}} != NULL) {
        {{param.client_unmarshaling|indent(8, False)}}
    }
{%- endif %}
{%- endfor %}
    if (NumApc != 0) {
        KiDeliverApc(MsgBufOffset, NumApc);
        if (MoreToCome) {
            NtTestAlert();
        }
    }
ClientPostMarshaling:
{%- for param in svc.params %}
{%- if param.client_post_marshaling %}
    {{param.client_post_marshaling|indent(4, False)}}
{%- endif %}
{%- endfor %}
    return Status;
}
{%- if not loop.last %}
{# #}
{%- endif %}
{% endfor %}
"""

# Types that can fit into a single machine word
SIMPLE_TYPES = ["BOOLEAN", "CHAR", "UCHAR", "SHORT", "USHORT", "LONG", "ULONG", "ULONG64",
                "ULONG_PTR", "SIZE_T", "MWORD", "NTSTATUS", "SECTION_INHERIT",
                "ACCESS_MASK", "LCID", "PVOID", "HANDLE", "GLOBAL_HANDLE",
                "PIO_APC_ROUTINE", "PTIMER_APC_ROUTINE", "PIO_INTERRUPT_SERVICE_THREAD_ENTRY",
                "EVENT_TYPE", "TIMER_TYPE", "SHUTDOWN_ACTION", "MEMORY_CACHING_TYPE",
                "HARDERROR_RESPONSE_OPTION", "HARDERROR_RESPONSE",
                "SYSTEM_INFORMATION_CLASS", "TOKEN_INFORMATION_CLASS",
                "MEMORY_INFORMATION_CLASS", "SECTION_INFORMATION_CLASS",
                "PROCESS_INFORMATION_CLASS", "THREAD_INFORMATION_CLASS",
                "FILE_INFORMATION_CLASS", "FS_INFORMATION_CLASS",
                "KEY_INFORMATION_CLASS", "KEY_VALUE_INFORMATION_CLASS",
                "PLUGPLAY_CONTROL_CLASS"]


def camel_case_to_upper_snake_case(name):
    result = re.sub('(.)([A-Z][a-z]+)', r'\1_\2', name)
    return re.sub('([a-z0-9])([A-Z])', r'\1_\2', result).upper()

def get_base_type(param):
    return re.search('::(.*)', param.param_type).group(1)


# Base type for all marshaller classes. The strategy here is that since
# we need to deal with many different cases as we have described above,
# including the cases where we need to examine multiple parameters to
# determine what to do, we will pass the entire parameter set of a system
# service to the marshaller, and have the marshaller visit each parameter
# node. If the parameter node has the right type, the marshaller will
# "dress the node", ie. inject the node with the generated marshaling code.
# Once that's done, the marshaller marks the parameter node as "marshaled"
# so that future visits by other marshallers will ignore the parameter.
class BaseMarshaller:
    # Virtual method for the derived marshaller classes. Visit each node
    # in the parameter list and determine if it is the right type. If it
    # is, inject the parameter node with the generated code and mark it
    # as marshaled.
    def marshal(self, params):
        raise NotImplementedError()


# Base class for all marshallers that only touch one single parameter
# (as opposed to, for instance, buffer parameters that need both a buffer
# pointer and buffer size).
class SingleParameterMarshaller(BaseMarshaller):
    def __init__(self, svc_name):
        self.svc_name = svc_name

    # Virtual method. Check the parameter and see if it is the right type to
    # be marshaled by this marshaller class.
    def accept(self, param):
        raise NotImplementedError()

    # Virtual method. Indicates whether client-side marshaling should check
    # if the parameter passed in is NULL.
    def should_check_null(self, param):
        raise NotImplementedError()

    def get_format_dict(self, p):
        return {
            "svc_name" : self.svc_name,
            "name" : p.name,
            "ty" : p.param_type,
            "idx" : p.idx,
            "optional" : p.optional,
            "dir_in" : p.dir_in
        }

    def format(self, p, tmplstr):
        template = Environment(loader=BaseLoader, trim_blocks=False,
                               lstrip_blocks=False).from_string(tmplstr)
        return template.render(self.get_format_dict(p))

    def marshal_param(self, p):
        p.server_decl = self.format(p, self.tmpl_server_decl)
        p.client_decl = self.format(p, self.tmpl_client_decl)
        p.check_null = self.should_check_null(p)
        p.client_marshaled_param = self.format(p, self.tmpl_client_marshaled_param)
        p.client_pre_marshaling = self.format(p, self.tmpl_client_pre_marshaling)
        p.client_marshaling = self.format(p, self.tmpl_client_marshaling)
        p.client_post_marshaling = self.format(p, self.tmpl_client_post_marshaling)
        p.client_unmarshaling = self.format(p, self.tmpl_client_unmarshaling)
        p.server_pre_marshaling = self.format(p, self.tmpl_server_pre_marshaling)
        p.server_marshaling = self.format(p, self.tmpl_server_marshaling)
        p.server_post_marshaling = self.format(p, self. tmpl_server_post_marshaling)
        p.marshaler_state_decl = ""

    def marshal(self, params):
        for p in params:
            if not p.marshaled and self.accept(p):
                self.marshal_param(p)
                p.marshaled = True


# Marshaller class for simple non-pointer (or pointers that we simply
# pass on to the server) types that can fit into one machine word.
# For these types we simply copy them into a seL4 message register.
# Note that we only accept IN parameters here. OUT parameter requires
# marshaling through the message buffer. Additionally, the parameter
# CANNOT be marked as OPTIONAL as it is not treated as a pointer to
# be marshaled.
class SimpleTypeMarshaller(SingleParameterMarshaller):
    def __init__(self, svc_name):
        self.tmpl_server_decl = "{{ty}} {{name}}"
        self.tmpl_client_decl = "{{ty}} {{name}}"
        self.tmpl_client_marshaled_param = "(MWORD) {{name}}"
        # No need to do anything to marshal parameters.
        self.tmpl_client_pre_marshaling = ""
        self.tmpl_client_marshaling = ""
        self.tmpl_client_post_marshaling = ""
        self.tmpl_client_unmarshaling = ""
        self.tmpl_server_pre_marshaling = "{{ty}} {{name}} = ({{ty}}) seL4_GetMR({{idx}});"
        self.tmpl_server_marshaling = ""
        self.tmpl_server_post_marshaling = ""
        super().__init__(svc_name)

    # For simple types we do not check if they are NULL (even if
    # it's a pointer type).
    def should_check_null(self, param):
        assert not param.optional
        return False

    def accept(self, p):
        if p.dir_out or p.optional:
            return False
        return p.param_type in SIMPLE_TYPES


# Marshaller class for pointers that can be marshaled simply by copying
# to and from the service message buffer. These parameters are marked
# with type ptr::BASE_TYPE. This corresponds to the first sub-case of
# pointer marshaling discussed above.
class SimplePointerMarshaller(SingleParameterMarshaller):
    def __init__(self, svc_name):
        self.tmpl_client_marshaled_param = "{{name}}Arg.Word"
        self.tmpl_server_decl = "{%- if dir_in %}P{{base_type}} {{name}}{%- else %}{{base_type}} *{{name}}{%- endif %}"
        self.tmpl_client_decl = self.tmpl_server_decl
        # For input types the client side marshaling reserves the buffer
        # space and copies the object into the service message buffer and
        # pass the offset and object size to the server. For output types
        # the copying is skipped.
        self.tmpl_client_pre_marshaling = "SERVICE_ARGUMENT {{name}}Arg = { .Word = 0 };"
        self.tmpl_client_marshaling = """if ({{name}} != NULL) {
    Status = KiServiceMarshalArgument(&{{name}}Arg, {%- if dir_in %}{{name}}{%- else %}NULL{%- endif %}, sizeof({{base_type}}), &MsgBufOffset);
    if (!NT_SUCCESS(Status)) {
        goto ClientPostMarshaling;
    }
}"""
        # We don't need to do anything when client gets the server response.
        self.tmpl_client_post_marshaling = ""
        # For output parameters, we need to copy the server response in the
        # service message buffer back to the client buffer.
        self.tmpl_client_unmarshaling = """assert({{name}}Arg.Word != 0);
memcpy({{name}}, KiServiceGetArgument((MWORD)__sel4_ipc_buffer, {{name}}Arg.Word), sizeof({{base_type}}));"""
        # On server side we retrives the pointer to the object in the thread's
        # service message buffer using the offset and buffer size passed in.
        # The server checks if the offset passed lies within the thread's service
        # message buffer and return error if it does not.
        self.tmpl_server_pre_marshaling = """SERVICE_ARGUMENT {{name}}Arg = { .Word = seL4_GetMR({{idx}}) };
{% if dir_in %}P{{base_type}} {{name}}{% else %}{{base_type}} *{{name}}{% endif %} = NULL;"""
        self.tmpl_server_marshaling = """if (!KiServiceValidateArgument({{name}}Arg.Word, sizeof({{base_type}}), {% if optional %}TRUE{% else %}FALSE{% endif %})) {
    DbgTrace("{{svc_name}}: Invalid argument at position {{idx+1}}. Argument is 0x%zx.\\n", {{name}}Arg.Word);
    Status = STATUS_INVALID_PARAMETER_{{idx+1}};
    goto ServerPostMarshaling_{{svc_name}};
}
{{name}} = KiServiceGetArgument(Thread->IpcBufferServerAddr, {{name}}Arg.Word);
"""
        # We don't need to do anything when the service handler returns.
        self.tmpl_server_post_marshaling = ""
        super().__init__(svc_name)

    def get_format_dict(self, p):
        return super().get_format_dict(p) | {
            "base_type" : get_base_type(p)
        }

    # If parameter is not optional, we should make sure that user has
    # passed a non-NULL pointer.
    def should_check_null(self, param):
        return not param.optional

    def accept(self, p):
        return "ptr::" in p.param_type


# Marshaller class for object types such as UnicodeString. The custom
# marshaling and unmarshaling functions are invoked instead of a direct
# copy. This corresponds to the second sub-case of pointer marshaling
# discussed above. Note that these can only be IN parameters.
class SingleObjectMarshaller(SingleParameterMarshaller):
    def __init__(self, svc_name, object_type, server_type, client_type,
                 marshal_func, validate_func, unmarshal_func):
        self.object_type = object_type
        self.server_type = server_type
        self.client_type = client_type
        self.marshal_func = marshal_func
        self.validate_func = validate_func
        self.unmarshal_func = unmarshal_func
        self.tmpl_server_decl = "{{server_type}} {{name}}"
        self.tmpl_client_decl = "{{client_type}} {{name}}"
        self.tmpl_client_marshaled_param = "{{name}}Arg.Word"
        self.tmpl_client_pre_marshaling = "SERVICE_ARGUMENT {{name}}Arg = { .Word = 0 };"
        # Call the custom marshaller function if the argument is not NULL
        self.tmpl_client_marshaling = """if ({{name}} != NULL) {
    Status = {{marshal_func}}(&{{name}}Arg, {{name}}, &MsgBufOffset);
    if (!NT_SUCCESS(Status)) {
        goto ClientPostMarshaling;
    }
}"""
        # We don't need to do anything when client gets the server response.
        self.tmpl_client_post_marshaling = ""
        # We don't need to do anything for OUT parameters because we don't support
        # OUT parameters for this type of marshaller.
        self.tmpl_client_unmarshaling = ""
        # On server side we call the custom validator function to validate the
        # argument passed by the client and call the custom unmarshal function to
        # retrive the pointer to the data passed in.
        self.tmpl_server_pre_marshaling = ""
        self.tmpl_server_marshaling = """if (!{{validate_func}}(Thread->IpcBufferServerAddr, seL4_GetMR({{idx}}), {% if optional %}TRUE{% else %}FALSE{% endif %})) {
    DbgTrace("{{svc_name}}: Invalid argument at position {{idx+1}}. Argument is 0x%zx.\\n",
             seL4_GetMR({{idx}}));
    break;
}
{{server_type}} {{name}} = {{unmarshal_func}}(Thread->IpcBufferServerAddr, seL4_GetMR({{idx}}));
"""
        # We don't need to do anything when the service handler returns.
        self.tmpl_server_post_marshaling = ""
        super().__init__(svc_name)
    def accept(self, p):
        if p.param_type == self.server_type:
            raise ValueError("Use " + self.object_type + " for " + self.server_type)
        if p.param_type == self.client_type:
            raise ValueError("Use " + self.object_type + " for " + self.client_type)
        if p.dir_out:
            return False
        return p.param_type == self.object_type

    # If parameter is not optional, we should make sure that user has
    # passed a non-NULL pointer.
    def should_check_null(self, param):
        return not param.optional

    def get_format_dict(self, p):
        return super().get_format_dict(p) | {
            "server_type" : self.server_type,
            "client_type" : self.client_type,
            "marshal_func" : self.marshal_func,
            "validate_func" : self.validate_func,
            "unmarshal_func" : self.unmarshal_func
        }


# Marshaller class for buffers specified by multiple parameters: buffer
# pointer, buffer size, and optionally a third parameter specifying the
# type of the buffer. For output buffers, we can also have an optional
# fourth parameter specifying the the result length of the output.
# Buffer parameters marked with buf::BUFFER_TYPE or buf#NUM::BUFFER_TYPE,
# where NUM is a number and BUFFER_TYPE is a user-defined identifier to
# distinguish the kind of buffers being marshaled (for instance, buf::Void
# will be marshaled by KiServiceMarshalBuffer, and buf::RegistryData will
# be marshaled by CmpMarshalRegData), will be examined and have their nodes
# dressed with the marshaling code. This corresponds to the third sub-case
# of pointer marshaling strategies discussed above.
class BufferMarshaller(BaseMarshaller):
    def __init__(self, svc_name, buffer_type, server_type,
                 client_type, client_marshal_func,
                 client_post_marshal_func, client_unmarshal_func,
                 server_marshal_func, server_post_marshal_func):
        self.svc_name = svc_name
        self.buffer_type = buffer_type
        self.server_type = server_type
        self.client_type = client_type
        self.client_marshal_func = client_marshal_func
        self.client_post_marshal_func = client_post_marshal_func
        self.client_unmarshal_func = client_unmarshal_func
        self.server_marshal_func = server_marshal_func
        self.server_post_marshal_func = server_post_marshal_func

    def format(self, pp, tmplstr):
        (p, sp, tp, lp) = pp
        format_dict = {
            "svc_name" : self.svc_name,
            "p" : p,
            "sp" : sp,
            "tp" : tp,
            "lp" : lp,
            "get_base_type" : get_base_type,
            "server_type" : self.server_type,
            "client_type" : self.client_type,
            "client_marshal_func" : self.client_marshal_func,
            "client_post_marshal_func" : self.client_post_marshal_func,
            "client_unmarshal_func" : self.client_unmarshal_func,
            "server_marshal_func" : self.server_marshal_func,
            "server_post_marshal_func" : self.server_post_marshal_func
        }
        template = Environment(loader=BaseLoader, trim_blocks=False,
                               lstrip_blocks=False).from_string(tmplstr)
        return template.render(format_dict)

    def marshal(self, params):
        for p in params:
            # Search for the parameter marked with buf::BASE_TYPE or
            # buf#idx::BASE_TYPE. If this one isn't, or it has already
            # been dressed with marshaling code, continue looking.
            if not "::" in p.param_type or p.marshaled:
                continue
            if "#" in p.param_type:
                buf_annot = re.search('(.*)#(.*)::(.*)', p.param_type).group(1)
                buf_idx = re.search('(.*)#(.*)::(.*)', p.param_type).group(2)
            else:
                buf_annot = re.search('(.*)::', p.param_type).group(1)
                buf_idx = ""
            # Didn't find one, so continue looking.
            if buf_annot != "buf":
                continue
            # We found one. Get its base type.
            base_type = get_base_type(p)
            # If the base type does not match, continue looking.
            if base_type != self.buffer_type:
                continue
            # We found one that matches our buffer type.
            idx_annot = ""
            if buf_idx != "":
                idx_annot += "#" + buf_idx
            # Search the parameter list to find its buffer type parameter
            # and buffer size parameter
            buftype_params = []
            for q in params:
                if not "buftype" + idx_annot + "::" in q.param_type:
                    continue
                buftype_params.append(q)
            bufsize_params = []
            for q in params:
                if not "bufsize" + idx_annot + "::" in q.param_type:
                    continue
                bufsize_params.append(q)
            if len(bufsize_params) == 0:
                raise ValueError(self.svc_name + ": Expected buffer size parameter")
            # We don't support buffers that are both IN and OUT. NT doesn't
            # have these anyway (all IN OUT parameters of NT system services
            # are covered by the case of SimplePointerMarshaller).
            if p.dir_in and p.dir_out:
                raise ValueError(self.svc_name + ": Buffer parameter " + p.name + " is marked both IN and OUT")
            if p.dir_in and len(bufsize_params) != 1:
                raise ValueError(self.svc_name + ": Invalid number of buffer size annotations")
            if p.dir_out and len(bufsize_params) > 2:
                raise ValueError(self.svc_name + ": Invalid number of buffer size annotations")
            if len(bufsize_params) == 1:
                bufsize_in = bufsize_params[0]
                bufsize_out = None
            else:
                in_params = []
                out_params = []
                for q in bufsize_params:
                    if q.dir_in and q.dir_out:
                        raise ValueError(self.svc_name + ": Buffer size parameter " + q.name + " cannot both be IN and OUT")
                    if q.dir_in:
                        in_params.append(q)
                    if q.dir_out:
                        out_params.append(q)
                    if len(in_params) != 1 or len(out_params) > 1:
                        raise ValueError(self.svc_name + ": Invalid number of buffer size notations")
                bufsize_in = in_params[0]
                bufsize_out = out_params[0]
            if len(buftype_params) > 1:
                raise ValueError(self.svc_name + ": Invalid buffer type annotation")
            # We now have everything we need. Generate the code.
            buftype_param = None
            if len(buftype_params) == 1:
                buftype_param = buftype_params[0]
            self.marshal_buffer_params(p, bufsize_in, buftype_param, bufsize_out)

    # Marshal buffer parameters that require only buffer pointer and buffer size.
    # p == buffer parameter, marked with buf(#[0-9]+)?::BASE_TYPE
    # sp == buffer size input parameter, marked with bufsize(#[0-9]+)?::BASE_TYPE
    # tp == buffer type parameter, marked with buftype(#[0-9]+)?::BASE_TYPE
    # lp == output length parameter, marked with bufsize::(#[0-9]+)?::BASE_TYPE
    # tp and lp may be None, in which case they don't exist
    def marshal_buffer_params(self, p, sp, tp, lp):
        assert not p.marshaled
        assert not sp.marshaled
        assert sp.dir_in
        assert not sp.dir_out
        if tp != None:
            assert not tp.marshaled
        if lp != None:
            assert not p.dir_in
            assert p.dir_out
            assert lp.dir_out
            assert not lp.dir_in
        pp = (p, sp, tp, lp)
        p.server_decl = self.format(pp, "{{server_type}} {{p.name}}")
        p.client_decl = self.format(pp, "{{client_type}} {{p.name}}")
        p.check_null = not p.optional
        p.client_marshaled_param = self.format(pp, "{{p.name}}Arg.Word")
        p.client_pre_marshaling = self.format(pp, "SERVICE_ARGUMENT {{p.name}}Arg = { .Word = 0 };")
        p.client_marshaling = self.format(pp, """Status = {{client_marshal_func}}({{p.name}}, {{sp.name}}{% if tp %}, {{tp.name}}{% endif %}, &{{p.name}}Arg, &{{sp.name}}Arg{% if tp %}, &{{tp.name}}Arg{% endif %}, {% if p.dir_in %}TRUE{% else %}FALSE{% endif %}, &MsgBufOffset);
if (!NT_SUCCESS(Status)) {
    goto ClientPostMarshaling;
}""")
        p.client_post_marshaling = self.format(pp, """{%- if client_post_marshal_func %}
{{client_post_marshal_func}}({{p.name}}, {{p.name}}Arg, {{sp.name}}Arg{% if tp %}, {{tp.name}}Arg{% endif %});
{%- endif %}""")
        p.client_unmarshaling = self.format(pp, "{%- if client_unmarshal_func %}{{client_unmarshal_func}}({{p.name}}, {{p.name}}Arg, {% if lp %}OFFSET_TO_ARG({{lp.name}}Arg.BufferStart, {{get_base_type(lp)}}){% else %}{{sp.name}}Arg.Word{% endif %});{%- endif %}")
        p.marshaler_state_decl = self.format(pp, "BOOLEAN {{p.name}}Mapped")
        p.server_pre_marshaling = self.format(pp, """SERVICE_ARGUMENT {{p.name}}Arg = { .Word = seL4_GetMR({{p.idx}}) };
{{server_type}} {{p.name}} = NULL;""")
        p.server_marshaling = self.format(pp, """{%- if server_marshal_func %}Thread->SavedParams.{{svc_name}}MarshalerState.{{p.name}}Mapped = FALSE;
if ({{p.name}}Arg.Word) {
    Status = {{server_marshal_func}}(Thread, &Thread->SavedParams.{{svc_name}}MarshalerState.{{p.name}}Mapped, &{{p.name}}, {{p.name}}Arg.Word, {{sp.name}}{% if tp %}, {{tp.name}}{% endif %});
    if (!NT_SUCCESS(Status)) {
        DbgTrace("{{svc_name}}: Unable to marshal parameter at position {{p.idx+1}}. Error status is 0x%x\\n", Status);
        goto ServerPostMarshaling_{{svc_name}};
    }
}
{%- else %}{{p.name}} = ({{server_type}}) {{p.name}}Arg.Word;
{%- endif %}
{%- if not p.optional %}
if ({{p.name}} == NULL) {
    DbgTrace("{{svc_name}}: Unable to marshal parameter at position {{p.idx+1}}.\\n");
    Status = STATUS_INVALID_PARAMETER_{{p.idx+1}};
    goto ServerPostMarshaling_{{svc_name}};
}
{%- endif %}""")
        p.server_post_marshaling = self.format(pp, """{%- if server_post_marshal_func %}if ({{p.name}} != NULL) {
    {{server_post_marshal_func}}(Thread->SavedParams.{{svc_name}}MarshalerState.{{p.name}}Mapped, {{p.name}}, {{sp.name}}{% if tp %}, {{tp.name}}{% endif %});
}
{%- endif %}""")
        p.marshaled = True
        # Since most of the work is done above for the buffer pointer parameter,
        # there is not much we need to do for buffer size and buffer type.
        sp.server_decl = self.format(pp, "{{get_base_type(sp)}} {{sp.name}}")
        sp.client_decl = self.format(pp, "{{get_base_type(sp)}} {{sp.name}}")
        sp.check_null = False
        sp.client_marshaled_param = self.format(pp, "{{sp.name}}Arg.Word")
        sp.client_pre_marshaling = self.format(pp, "SERVICE_ARGUMENT {{sp.name}}Arg = { .Word = 0 };")
        sp.client_marshaling = ""
        sp.client_post_marshaling = ""
        sp.client_unmarshaling = ""
        sp.server_pre_marshaling = self.format(pp, "{{get_base_type(sp)}} {{sp.name}} = ({{get_base_type(sp)}}) seL4_GetMR({{sp.idx}});")
        sp.server_marshaling = ""
        sp.server_post_marshaling = ""
        sp.marshaler_state_decl = ""
        sp.marshaled = True
        if tp != None:
            tp.server_decl = self.format(pp, "{{get_base_type(tp)}} {{tp.name}}")
            tp.client_decl = self.format(pp, "{{get_base_type(tp)}} {{tp.name}}")
            tp.check_null = False
            tp.client_marshaled_param = self.format(pp, "{{tp.name}}Arg.Word")
            tp.client_pre_marshaling = self.format(pp, "SERVICE_ARGUMENT {{tp.name}}Arg = { .Word = 0 };")
            tp.client_marshaling = ""
            tp.client_post_marshaling = ""
            tp.client_unmarshaling = ""
            tp.server_pre_marshaling = self.format(pp, "{{get_base_type(tp)}} {{tp.name}} = ({{get_base_type(tp)}}) seL4_GetMR({{tp.idx}});")
            tp.server_marshaling = ""
            tp.server_post_marshaling = ""
            tp.marshaler_state_decl = ""
            tp.marshaled = True
        # For the result length parameter, we marshal it like a SimplePointer,
        # ie. ptr::BASE_TYPE, except it's always non-optional, despite the
        # parameter annotation in syssvc.xml. This is because we need it to
        # copy the result data in the service message buffer back to the user.
        if lp != None:
            lp.server_decl = self.format(pp, "{{get_base_type(lp)}} *{{lp.name}}")
            lp.client_decl = self.format(pp, "{{get_base_type(lp)}} *{{lp.name}}")
            lp.check_null = not lp.optional
            lp.client_marshaled_param = self.format(pp, "{{lp.name}}Arg.Word")
            lp.client_pre_marshaling = self.format(pp, "SERVICE_ARGUMENT {{lp.name}}Arg = { .Word = 0 };")
            lp.client_marshaling = self.format(pp, """Status = KiServiceMarshalArgument(&{{lp.name}}Arg, NULL, sizeof({{get_base_type(lp)}}), &MsgBufOffset);
if (!NT_SUCCESS(Status)) {
    goto ClientPostMarshaling;
}""")
            lp.client_post_marshaling = ""
            lp.client_unmarshaling = self.format(pp, """assert({{lp.name}}Arg.Word != 0);
assert({{lp.name}}Arg.BufferSize == sizeof({{get_base_type(lp)}}));
*{{lp.name}} = OFFSET_TO_ARG({{lp.name}}Arg.BufferStart, {{get_base_type(lp)}});""")
            lp.server_pre_marshaling = self.format(pp, """SERVICE_ARGUMENT {{lp.name}}Arg = { .Word = seL4_GetMR({{lp.idx}}) };
{{get_base_type(lp)}} *{{lp.name}} = NULL;""")
            lp.server_marshaling = self.format(pp, """if (!KiServiceValidateArgument({{lp.name}}Arg.Word, sizeof({{get_base_type(lp)}}), FALSE)) {
    DbgTrace("{{svc_name}}: Invalid argument at position {{lp.idx+1}}. Argument is 0x%zx.\\n", {{lp.name}}Arg.Word);
    Status = STATUS_INVALID_PARAMETER_{{lp.idx+1}};
    goto ServerPostMarshaling_{{svc_name}};
}
{{lp.name}} = KiServiceGetArgument(Thread->IpcBufferServerAddr, {{lp.name}}Arg.Word);
assert({{lp.name}} != NULL);""")
            lp.server_post_marshaling = ""
            lp.marshaler_state_decl = ""
            lp.marshaled = True


# Class for a service parameter.
class ServiceParameter:
    # Record the parameter name, annotations, and parameter type, so the
    # marshaller can dress the node with the correct marshaling code.
    def __init__(self, idx, annotations, param_type, name):
        self.idx = idx
        self.name = name
        self.param_type = param_type
        self.marshaled = False
        annotation_list = []
        self.optional = False
        self.dir_in = False
        self.dir_out = False
        if "in" in annotations:
            self.dir_in = True
            annotation_list.append("IN")
        if "out" in annotations:
            self.dir_out = True
            annotation_list.append("OUT")
        if "opt" in annotations:
            self.optional = True
            annotation_list.append("OPTIONAL")
        if not self.dir_in and not self.dir_out:
            raise ValueError("Parameter " + name + " must have directional annotations (either IN or OUT)")
        self.annotations = " ".join(annotation_list)


# Class for a system service.
class Service:
    # Record the service name, tag, parameter list, and invoke the marshallers
    # to generate the parameter marshaling code.
    def __init__(self, server_name, client_name, params, client_only, wdmsvc):
        self.server_name = server_name
        self.client_name = client_name
        self.enum_tag = camel_case_to_upper_snake_case(server_name)
        self.params = params
        self.client_only = client_only
        self.server_param_indent = " " * (len("NTSTATUS") + len(server_name) + 2)
        self.msglength = len(params)+1
        if len(params) == 0 or wdmsvc:
            self.ntapi = False
        else:
            self.ntapi = True
        if self.ntapi:
            self.client_param_indent = " " * (len("NTSTATUS NTAPI") + len(client_name) + 2)
        else:
            self.client_param_indent = " " * (len("NTSTATUS") + len(client_name) + 2)
        marshallers = [
            SimpleTypeMarshaller(server_name),
            SimplePointerMarshaller(server_name),
            SingleObjectMarshaller(server_name, object_type = "UnicodeString",
                                   server_type = "PCSTR",
                                   client_type = "PUNICODE_STRING",
                                   marshal_func = "KiMarshalUnicodeString",
                                   validate_func = "KiValidateUnicodeString",
                                   unmarshal_func = "KiServiceGetArgument"),
            SingleObjectMarshaller(server_name, object_type = "AnsiString",
                                   server_type = "PCSTR",
                                   client_type = "PCSTR",
                                   marshal_func = "KiMarshalAnsiString",
                                   validate_func = "KiValidateUnicodeString",
                                   unmarshal_func = "KiServiceGetArgument"),
            SingleObjectMarshaller(server_name, object_type = "ObjectAttributes",
                                   server_type = "OB_OBJECT_ATTRIBUTES",
                                   client_type = "POBJECT_ATTRIBUTES",
                                   marshal_func = "KiMarshalObjectAttributes",
                                   validate_func = "KiValidateObjectAttributes",
                                   unmarshal_func = "KiUnmarshalObjectAttributes"),
            SingleObjectMarshaller(server_name, object_type = "AnsiObjectAttributes",
                                   server_type = "OB_OBJECT_ATTRIBUTES",
                                   client_type = "POBJECT_ATTRIBUTES_ANSI",
                                   marshal_func = "KiMarshalObjectAttributesA",
                                   validate_func = "KiValidateObjectAttributesA",
                                   unmarshal_func = "KiUnmarshalObjectAttributesA"),
            BufferMarshaller(server_name, buffer_type = "Void",
                             server_type = "PVOID", client_type = "PVOID",
                             client_marshal_func = "KiServiceMarshalBuffer",
                             client_post_marshal_func = "",
                             client_unmarshal_func = "KiServiceUnmarshalBuffer",
                             server_marshal_func = "KiServiceMapBuffer",
                             server_post_marshal_func = "KiServiceUnmapBuffer"),
            BufferMarshaller(server_name, buffer_type = "InputIoBuffer",
                             server_type = "PVOID", client_type = "PVOID",
                             client_marshal_func = "KiServiceMarshalBuffer",
                             client_post_marshal_func = "",
                             client_unmarshal_func = "",
                             server_marshal_func = "",
                             server_post_marshal_func = ""),
            BufferMarshaller(server_name, buffer_type = "KeyValueInfoBuffer",
                             server_type = "PVOID", client_type = "PVOID",
                             client_marshal_func = "CmpMarshalKeyValueInfoBuffer",
                             client_post_marshal_func = "",
                             client_unmarshal_func = "KiServiceUnmarshalBuffer",
                             server_marshal_func = "KiServiceMapBuffer",
                             server_post_marshal_func = "KiServiceUnmapBuffer"),
            BufferMarshaller(server_name, buffer_type = "UnicodeRegistryData",
                             server_type = "PVOID", client_type = "PVOID",
                             client_marshal_func = "CmpMarshalRegData",
                             client_post_marshal_func = "CmpFreeMarshaledRegData",
                             client_unmarshal_func = "",
                             server_marshal_func = "KiServiceMapBuffer",
                             server_post_marshal_func = "KiServiceUnmapBuffer"),
            BufferMarshaller(server_name, buffer_type = "AnsiRegistryData",
                             server_type = "PVOID", client_type = "PVOID",
                             client_marshal_func = "CmpMarshalRegDataA",
                             client_post_marshal_func = "",
                             client_unmarshal_func = "",
                             server_marshal_func = "KiServiceMapBuffer",
                             server_post_marshal_func = "KiServiceUnmapBuffer")
        ]
        for m in marshallers:
            m.marshal(params)
        for p in params:
            if not p.marshaled:
                raise ValueError(server_name + ": Unable to marshal parameter " + p.name)
        self.has_marshaler_state = False
        for p in params:
            if p.marshaler_state_decl:
                self.has_marshaler_state = True
                break


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
        params = []
        ansi_params = []
        has_unicode_string = False
        has_unicode_out_param = False
        idx = 0
        for param in svc.getElementsByTagName("parameter"):
            annotation = str(param.getAttribute("annotation"))
            param_name = str(param.getAttribute("name"))
            param_type = str(param.getAttribute("type"))
            params.append(ServiceParameter(idx, annotation, param_type, param_name))
            if param_type == "UnicodeString":
                has_unicode_string = True
                ansi_params.append(ServiceParameter(idx, annotation, "AnsiString", param_name))
            elif param_type == "ObjectAttributes":
                has_unicode_string = True
                ansi_params.append(ServiceParameter(idx, annotation, "AnsiObjectAttributes", param_name))
            elif param_type == "buf::UnicodeRegistryData":
                has_unicode_string = True
                ansi_params.append(ServiceParameter(idx, annotation, "buf::AnsiRegistryData", param_name))
            else:
                ansi_params.append(ServiceParameter(idx, annotation, param_type, param_name))
            if "out" in annotation and "unicode" in annotation:
                has_unicode_out_param = True
            idx += 1
        # If the service has Unicode OUT parameters, we need to generate two services on the
        # server side, one that outputs UTF-8 (which corresponds to the "A"-version on the
        # client side), and one that outputs UTF-16 (which corresponds to the non-"A" version
        # on the client side). The input parameters on the server side are always in UTF-8,
        # because we marshal Unicode input parameters on the client side.
        if has_unicode_out_param:
            svc_list.append(Service(name+"W", name, params, client_only = False, wdmsvc = wdmsvc))
            svc_list.append(Service(name+"A", name+"A", ansi_params, client_only = False, wdmsvc = wdmsvc))
        else:
            svc_list.append(Service(name, name, params, client_only = False, wdmsvc = wdmsvc))
            if has_unicode_string:
                svc_list.append(Service(name, name+"A", ansi_params, client_only = True, wdmsvc = wdmsvc))

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
    generate_file(SVC_PARAMS_GEN_H_TEMPLATE, server_syssvc_list + server_wdmsvc_list, svc_params_gen_h, wdmsvc = False, server_side = True)

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
