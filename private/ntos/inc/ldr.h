#pragma once

#include <sel4/sel4.h>

#define DOS_DEVICES_DIRECTORY		"\\??"
#define BOOTMODULE_OBJECT_DIRECTORY	DOS_DEVICES_DIRECTORY "\\BootModules"
#define INITIAL_SYSTEM_ROOT_U		u"\\\\?\\BootModules"
#define NTDLL_NAME_NO_EXT		"ntdll"
#define NTDLL_NAME			NTDLL_NAME_NO_EXT ".dll"
#define NTDLL_PATH			BOOTMODULE_OBJECT_DIRECTORY "\\" NTDLL_NAME
#define SMSS_EXE_NAME			"smss.exe"
#define SMSS_EXE_PATH			BOOTMODULE_OBJECT_DIRECTORY "\\" SMSS_EXE_NAME

/* boot.c */
NTSTATUS LdrLoadBootModules();
