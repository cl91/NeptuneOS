#pragma once

#include <lnxdrv.h>
#include "../../../linux/arch/ntos/include/ntlnxdrv.h"

/* Some sanity checks to make sure we have consistent definitions across LNXDRV */
C_ASSERT(MDL_PFN_ATTR_BITS == LNXDRV_PFN_ATTR_BITS);
C_ASSERT(MDL_PFN_PAGE_COUNT_BITS == LNXDRV_PFN_PAGE_COUNT_BITS);
C_ASSERT(MDL_PFN_ATTR_LARGE_PAGE == LNXDRV_PFN_ATTR_LARGE_PAGE);
C_ASSERT(MDL_PFN_ATTR_CACHED == LNXDRV_PFN_ATTR_CACHED);
C_ASSERT(MDL_PFN_ATTR_WC == LNXDRV_PFN_ATTR_WC);
C_ASSERT(MDL_PFN_ATTR_WT == LNXDRV_PFN_ATTR_WT);
C_ASSERT(MDL_PFN_ATTR_UNCACHED == LNXDRV_PFN_ATTR_UNCACHED);

#define LNXDRV_TAG	'LNXD'

#define LoopOverList(Entry, ListHead, Type, Field)			\
    for (Type *Entry = CONTAINING_RECORD((ListHead)->Flink, Type, Field), \
	     *__LoopOverList_flink = CONTAINING_RECORD((Entry)->Field.Flink, Type, Field); \
	 &(Entry)->Field != (ListHead); Entry = __LoopOverList_flink,	\
	     __LoopOverList_flink = CONTAINING_RECORD((__LoopOverList_flink)->Field.Flink, Type, Field))
