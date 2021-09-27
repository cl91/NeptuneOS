#pragma once

#include <kernel/gen_config.h>

#include <nt.h>
#include <assert.h>
#include <compile_assert.h>
#include <string.h>
#include <gnu.h>

#include <debug.h>

#include "ntosdef.h"
#include "ob.h"
#include "ke.h"
#include "mm.h"
#include "ex.h"
#include "io.h"
#include "ps.h"
#include "ldr.h"

#ifdef CONFIG_DEBUG_BUILD
VOID MmDbgDumpCapTreeNode(IN PCAP_TREE_NODE Node);
VOID MmDbgDumpUntypedInfo();
VOID MmDbgDumpPagingStructure(IN PPAGING_STRUCTURE Paging);
VOID MmDbgDumpPagingStructureRecursively(IN PPAGING_STRUCTURE Paging);
VOID MmDbgDumpSection(IN PSECTION Section);
VOID MmDbgDumpVad(PMMVAD Vad);
VOID MmDbgDumpVSpace(PVIRT_ADDR_SPACE VSpace);
VOID KeDbgDumpIPCError(IN int Error);
VOID IoDbgDumpFileObject(IN PFILE_OBJECT File);
#else
#define MmDbgDumpCapTreeNode(x)
#define MmDbgDumpUntypedInfo()
#define MmDbgDumpPagingStructure(x)
#define MmDbgDumpPagingStructureRecursively(x)
#define MmDbgDumpSection(x)
#define MmDbgDumpVad(x)
#define MmDbgDumpVSpace(x)
#define KeDbgDumpIPCError(x)
#define IoDbgDumpFileObject(x)
#endif
