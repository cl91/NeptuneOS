/*
 * COPYRIGHT:       See COPYING in the top level directory
 * PROJECT:         ReactOS system libraries
 * FILE:            lib/rtl/amd64/slist.S
 * PURPOSE:         Rtl Interlocked Functions for amd64
 * PROGRAMMERS:     Timo Kreuzer
 */

#include <asm.inc>
#include <ksamd64.h>

/*
typedef union DECLSPEC_ALIGN(16) _SLIST_HEADER
{
    struct
    {
        ULONGLONG Alignment;
        ULONGLONG Region;
    };
    struct
    {
        ULONGLONG Depth:16;
        ULONGLONG Sequence:9;
        ULONGLONG NextEntry:39;
        ULONGLONG HeaderType:1;
        ULONGLONG Init:1;
        ULONGLONG Reserved:59;
        ULONGLONG Region:3;
    } Header8;
    struct
    {
        ULONGLONG Depth:16;
        ULONGLONG Sequence:48;
        ULONGLONG HeaderType:1;
        ULONGLONG Init:1;
        ULONGLONG Reserved:2;
        ULONGLONG NextEntry:60;
    } Header16;
    struct
    {
        ULONGLONG Depth:16;
        ULONGLONG Sequence:48;
        ULONGLONG HeaderType:1;
        ULONGLONG Reserved:3;
        ULONGLONG NextEntry:60;
    } HeaderX64;
} SLIST_HEADER, *PSLIST_HEADER;
*/

#define SLIST8A_DEPTH_MASK       HEX(000000000000FFFF)
#define SLIST8A_DEPTH_INC        HEX(0000000000000001)
#define SLIST8A_SEQUENCE_MASK    HEX(0000000001FF0000)
#define SLIST8A_SEQUENCE_INC     HEX(0000000000010000)
#define SLIST8A_NEXTENTRY_MASK   HEX(FFFFFFFFFE000000)
#define SLIST8A_NEXTENTRY_SHIFT  21
#define SLIST8B_HEADERTYPE_MASK  HEX(0000000000000001)
#define SLIST8B_INIT_MASK        HEX(0000000000000002)
#define SLIST8B_REGION_MASK      HEX(E000000000000000)
#define SLIST8_POINTER_MASK      HEX(000007FFFFFFFFFF)

#define SLIST16A_DEPTH_MASK      HEX(000000000000FFFF)
#define SLIST16A_DEPTH_INC       HEX(0000000000000001)
#define SLIST16A_SEQUENCE_MASK   HEX(FFFFFFFFFFFF0000)
#define SLIST16A_SEQUENCE_INC    HEX(0000000000010000)
#define SLIST16B_HEADERTYPE_MASK HEX(0000000000000001)
#define SLIST16B_INIT_MASK       HEX(0000000000000002)
#define SLIST16B_NEXTENTRY_MASK  HEX(FFFFFFFFFFFFFFF0)


/* FUNCTIONS ****************************************************************/

.code64

PUBLIC RtlInterlockedPopEntrySList
PUBLIC RtlInterlockedPushEntrySList
PUBLIC RtlInterlockedFlushSList

/* PSLIST_ENTRY
 * NTAPI
 * RtlInterlockedPopEntrySList(
 *     IN PSLIST_HEADER ListHead);
 */
FUNC RtlInterlockedPopEntrySList
    mov [rsp + P3Home], rbx
    .savereg rbx, P3Home
    .endprolog

    /* Load ListHead->Region into rdx */
    mov rdx, [rcx + 8]

    /* Load ListHead->Alignment into rax */
    mov rax, [rcx]

    /* This is a 16 byte header
       rcx == ListHead
       rdx == ListHead->Region
       rax == ListHead->Alignment */

    /* Copy rcx to r8, as we need rcx for the exchange */
    mov r8, rcx

GLOBAL_LABEL RtlpInterlockedPopEntrySListResume16

    /* Set r9 = ListHead->NextEntry and check if it is NULL */
    mov r9, rdx
    and r9, SLIST16B_NEXTENTRY_MASK
    jz RtlInterlockedPopEntrySListEmpty16

GLOBAL_LABEL RtlpInterlockedPopEntrySListFault16

    /* Set NewListHead.Next = ListHead->NextEntry->Next */
    mov rcx, [r9]

    /* Set NewListHead.HeaderType = 1 and  NewListHead.Init = 1 */
    or rcx, (SLIST16B_HEADERTYPE_MASK or SLIST16B_INIT_MASK)

    /* Copy Depth and Sequence number and adjust Depth */
    lea rbx, [rax - SLIST16A_DEPTH_INC]

GLOBAL_LABEL RtlpInterlockedPopEntrySListEnd16

    /* If [r8] equals rdx:rax, exchange it with rcx:rbx */
    lock cmpxchg16b [r8]

    /* If not equal, retry with rdx:rax, being the content of [r8] now */
    jne RtlpInterlockedPopEntrySListResume16

    /* Copy the old NextEntry pointer to rax */
    mov rax, rdx
    and rax, SLIST16B_NEXTENTRY_MASK

    /* Return */
    mov rbx, [rsp + P3Home]
    ret

RtlInterlockedPopEntrySListEmpty16:

    xor rax, rax
    mov rbx, [rsp + P3Home]
    ret
ENDFUNC


/* PSLIST_ENTRY
 * NTAPI
 * RtlInterlockedPushEntrySList(
 *     IN PSLIST_HEADER ListHead,
 *     IN PSLIST_ENTRY ListEntry);
 */
FUNC RtlInterlockedPushEntrySList
    mov [rsp + P3Home], rbx
    .savereg rbx, P3Home
    .endprolog

#if DBG
    /* Make sure the ListEntry is 16 bytes aligned */
    test rdx, HEX(0F)
    jz RtlpInterlockedPushEntrySListChecked
    /* Not aligned, raise an assertion */
    int HEX(2C)
RtlpInterlockedPushEntrySListChecked:
#endif

    /* Load ListHead->Alignment into rax */
    mov rax, [rcx]

    /* This is a 16 byte header
       rcx = ListHead
       rdx = ListEntry
       rax = ListHead->Alignment */

    /* Copy rcx/rdx to r8/r9, as we need rcx/rdx for the exchange */
    mov r8, rcx
    mov r9, rdx

    /* Set NewListHead.NextEntry = ListEntry */
    mov rcx, rdx

    /* Set NewListHead.HeaderType = 1 and NewListHead.Init = 1 */
    or rcx, (SLIST16B_HEADERTYPE_MASK or SLIST16B_INIT_MASK)

    /* Set rdx = ListHead->Region */
    mov rdx, [r8 + 8]

RtlInterlockedPushEntrySListLoop16:
    /* r8 = ListHead
       r9 = ListEntry
       rax = ListHead->Alignment
       rdx = ListHead->Region
    */

    /* Move ListHead->NextEntry to rbx */
    mov rbx, rdx
    and rbx, SLIST16B_NEXTENTRY_MASK

    /* Store next pointer in ListEntry->Next */
    mov [r9], rbx

    /* Copy and increment Depth and Sequence number to rbx */
    lea rbx, [rax + SLIST16A_DEPTH_INC + SLIST16A_SEQUENCE_INC]

    /* If [r8] equals rdx:rax, exchange it with rcx:rbx */
    lock cmpxchg16b [r8]

    /* If not equal, retry with rdx:rax, being the content of [r8] now */
    jne RtlInterlockedPushEntrySListLoop16

    /* Copy the old NextEntry pointer to rax */
    mov rax, rdx
    and rax, SLIST16B_NEXTENTRY_MASK

    /* Return */
    mov rbx, [rsp + P3Home]
    ret

ENDFUNC


/* PSLIST_ENTRY
 * NTAPI
 * RtlInterlockedFlushSList(
 *     IN PSLIST_HEADER ListHead);
 */
FUNC RtlInterlockedFlushSList

    mov [rsp + P3Home], rbx
    .savereg rbx, P3Home
    .endprolog

    /* Load ListHead->Region into rdx */
    mov rdx, [rcx + 8]

    /* Load ListHead->Alignment into rax */
    mov rax, [rcx]

    /* We have a 16 byte header
        rcx = ListHead
        rax = ListHead->Alignment
        rdx = ListHead->Region
    */

    /* Load ListHead into r8, as we need rcx for the exchange */
    mov r8, rcx

    /* Initialize an ampty NewListHead in rcx:rbx */
    xor rbx, rbx
    mov rcx, (SLIST16B_HEADERTYPE_MASK or SLIST16B_INIT_MASK)

RtlInterlockedFlushSListLoop16:

    /* If [r8] equals rdx:rax, exchange it with rcx:rbx */
    lock cmpxchg16b [r8]

    /* If not equal, retry with rdx:rax, being the content of [r8] now */
    jne RtlInterlockedFlushSListLoop16

    /* Copy the old NextEntry pointer to rax */
    mov rax, rdx
    and rax, SLIST16B_NEXTENTRY_MASK

    /* Return */
    mov rbx, [rsp + P3Home]
    ret

ENDFUNC

END

