#include <nt.h>
#include <ntddkbd.h>
#include <assert.h>
#include <stdarg.h>
#include <string.h>
#include <stdio.h>

#define DbgTrace(...) { DbgPrint("SMSS %s:  ", __func__); DbgPrint(__VA_ARGS__); }

#define RET_ERR_EX(Expr, OnError)					\
    {NTSTATUS Status = (Expr); if (!NT_SUCCESS(Status)) {		\
	    DbgPrint("Expression %s in function %s @ %s:%d returned"	\
		     " error 0x%x\n",					\
		     #Expr, __func__, __FILE__, __LINE__, Status);	\
	    {OnError;} return Status; }}
#define RET_ERR(Expr)	RET_ERR_EX(Expr, {})

#define DECLARE_UNICODE_STRING(Name, Ptr, Len)				\
    UNICODE_STRING Name = { .Length = Len, .MaximumLength = Len,	\
	.Buffer = Ptr }

#define LoopOverList(Entry, ListHead, Type, Field)			\
    for (Type *Entry = CONTAINING_RECORD((ListHead)->Flink, Type, Field), \
	     *__LoopOverList_flink = CONTAINING_RECORD((Entry)->Field.Flink, Type, Field); \
	 &(Entry)->Field != (ListHead); Entry = __LoopOverList_flink,	\
	     __LoopOverList_flink = CONTAINING_RECORD((__LoopOverList_flink)->Field.Flink, Type, Field))

FORCEINLINE PVOID SmAllocatePool(IN ULONG Size)
{
    return RtlAllocateHeap(RtlGetProcessHeap(), HEAP_ZERO_MEMORY, Size);
}

FORCEINLINE VOID SmFreePool(IN PVOID Ptr)
{
    RtlFreeHeap(RtlGetProcessHeap(), 0, Ptr);
}

typedef struct _KBD_RECORD {
    USHORT wVirtualScanCode;
    ULONG dwControlKeyState;
    UCHAR AsciiChar;
    BOOLEAN bKeyDown;
} KBD_RECORD, *PKBD_RECORD;

#define RIGHT_ALT_PRESSED     0x0001	// the right alt key is pressed.
#define LEFT_ALT_PRESSED      0x0002	// the left alt key is pressed.
#define RIGHT_CTRL_PRESSED    0x0004	// the right ctrl key is pressed.
#define LEFT_CTRL_PRESSED     0x0008	// the left ctrl key is pressed.
#define SHIFT_PRESSED         0x0010	// the shift key is pressed.
#define NUMLOCK_ON            0x0020	// the numlock light is on.
#define SCROLLLOCK_ON         0x0040	// the scrolllock light is on.
#define CAPSLOCK_ON           0x0080	// the capslock light is on.
#define ENHANCED_KEY          0x0100	// the key is enhanced.

/* keytrans.c */
VOID IntTranslateKey(IN PKEYBOARD_INPUT_DATA InputData,
		     OUT KBD_RECORD *kbd_rec);

/* main.c */
NTSTATUS SmPrint(PCSTR Format, ...) __attribute__((format(printf, 1, 2)));

/* reg.c */
NTSTATUS SmCreateRegistryKey(IN PCSTR Path,
			     IN BOOLEAN Volatile,
			     OUT HANDLE *Handle);
NTSTATUS SmSetRegKeyValue(IN HANDLE KeyHandle,
			  IN PCSTR ValueName,
			  IN ULONG Type,
			  IN PVOID Data,
			  IN ULONG DataSize);
NTSTATUS SmInitRegistry();

/* hw.c */
NTSTATUS SmInitHardwareDatabase();
