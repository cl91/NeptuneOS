/*
 * PROJECT:         ReactOS Kernel
 * LICENSE:         GPL - See COPYING in the top level directory
 * FILE:            ntoskrnl/fsrtl/name.c
 * PURPOSE:         Provides name parsing and other support routines for FSDs
 * PROGRAMMERS:     Alex Ionescu (alex.ionescu@reactos.org)
 *                  Filip Navara (navaraf@reactos.org)
 *                  Pierre Schweitzer (pierre.schweitzer@reactos.org)
 *                  Aleksey Bragin (aleksey@reactos.org)
 */

/* INCLUDES ******************************************************************/

#include <wdmp.h>

/* DEFINITIONS ***************************************************************/

#define ANSI_DOS_STAR                   ('<')
#define ANSI_DOS_QM                     ('>')
#define ANSI_DOS_DOT                    ('"')

#define DOS_STAR                        (L'<')
#define DOS_QM                          (L'>')
#define DOS_DOT                         (L'"')

#define FSRTL_FAT_LEGAL                 0x01
#define FSRTL_HPFS_LEGAL                0x02
#define FSRTL_NTFS_LEGAL                0x04
#define FSRTL_WILD_CHARACTER            0x08
#define FSRTL_OLE_LEGAL                 0x10
#define FSRTL_NTFS_STREAM_LEGAL         (FSRTL_NTFS_LEGAL | FSRTL_OLE_LEGAL)

static const UCHAR LegalAnsiCharacterArray[] = {
    0,                                                                          /* CTRL+@, 0x00 */
    FSRTL_OLE_LEGAL,                                                            /* CTRL+A, 0x01 */
    FSRTL_OLE_LEGAL,                                                            /* CTRL+B, 0x02 */
    FSRTL_OLE_LEGAL,                                                            /* CTRL+C, 0x03 */
    FSRTL_OLE_LEGAL,                                                            /* CTRL+D, 0x04 */
    FSRTL_OLE_LEGAL,                                                            /* CTRL+E, 0x05 */
    FSRTL_OLE_LEGAL,                                                            /* CTRL+F, 0x06 */
    FSRTL_OLE_LEGAL,                                                            /* CTRL+G, 0x07 */
    FSRTL_OLE_LEGAL,                                                            /* CTRL+H, 0x08 */
    FSRTL_OLE_LEGAL,                                                            /* CTRL+I, 0x09 */
    FSRTL_OLE_LEGAL,                                                            /* CTRL+J, 0x0a */
    FSRTL_OLE_LEGAL,                                                            /* CTRL+K, 0x0b */
    FSRTL_OLE_LEGAL,                                                            /* CTRL+L, 0x0c */
    FSRTL_OLE_LEGAL,                                                            /* CTRL+M, 0x0d */
    FSRTL_OLE_LEGAL,                                                            /* CTRL+N, 0x0e */
    FSRTL_OLE_LEGAL,                                                            /* CTRL+O, 0x0f */
    FSRTL_OLE_LEGAL,                                                            /* CTRL+P, 0x10 */
    FSRTL_OLE_LEGAL,                                                            /* CTRL+Q, 0x11 */
    FSRTL_OLE_LEGAL,                                                            /* CTRL+R, 0x12 */
    FSRTL_OLE_LEGAL,                                                            /* CTRL+S, 0x13 */
    FSRTL_OLE_LEGAL,                                                            /* CTRL+T, 0x14 */
    FSRTL_OLE_LEGAL,                                                            /* CTRL+U, 0x15 */
    FSRTL_OLE_LEGAL,                                                            /* CTRL+V, 0x16 */
    FSRTL_OLE_LEGAL,                                                            /* CTRL+W, 0x17 */
    FSRTL_OLE_LEGAL,                                                            /* CTRL+X, 0x18 */
    FSRTL_OLE_LEGAL,                                                            /* CTRL+Y, 0x19 */
    FSRTL_OLE_LEGAL,                                                            /* CTRL+Z, 0x1a */
    FSRTL_OLE_LEGAL,                                                            /* CTRL+[, 0x1b */
    FSRTL_OLE_LEGAL,                                                            /* CTRL+\, 0x1c */
    FSRTL_OLE_LEGAL,                                                            /* CTRL+], 0x1d */
    FSRTL_OLE_LEGAL,                                                            /* CTRL+^, 0x1e */
    FSRTL_OLE_LEGAL,                                                            /* CTRL+_, 0x1f */
    FSRTL_OLE_LEGAL | FSRTL_FAT_LEGAL | FSRTL_HPFS_LEGAL | FSRTL_NTFS_LEGAL,    /* ` ',    0x20 */
    FSRTL_FAT_LEGAL | FSRTL_HPFS_LEGAL | FSRTL_NTFS_LEGAL,                      /* `!',    0x21 */
    FSRTL_OLE_LEGAL | FSRTL_WILD_CHARACTER,                                     /* `"',    0x22 */
    FSRTL_OLE_LEGAL | FSRTL_FAT_LEGAL | FSRTL_HPFS_LEGAL | FSRTL_NTFS_LEGAL,    /* `#',    0x23 */
    FSRTL_OLE_LEGAL | FSRTL_FAT_LEGAL | FSRTL_HPFS_LEGAL | FSRTL_NTFS_LEGAL,    /* `$',    0x24 */
    FSRTL_OLE_LEGAL | FSRTL_FAT_LEGAL | FSRTL_HPFS_LEGAL | FSRTL_NTFS_LEGAL,    /* `%',    0x25 */
    FSRTL_OLE_LEGAL | FSRTL_FAT_LEGAL | FSRTL_HPFS_LEGAL | FSRTL_NTFS_LEGAL,    /* `&',    0x26 */
    FSRTL_OLE_LEGAL | FSRTL_FAT_LEGAL | FSRTL_HPFS_LEGAL | FSRTL_NTFS_LEGAL,    /* `'',    0x27 */
    FSRTL_OLE_LEGAL | FSRTL_FAT_LEGAL | FSRTL_HPFS_LEGAL | FSRTL_NTFS_LEGAL,    /* `(',    0x28 */
    FSRTL_OLE_LEGAL | FSRTL_FAT_LEGAL | FSRTL_HPFS_LEGAL | FSRTL_NTFS_LEGAL,    /* `)',    0x29 */
    FSRTL_OLE_LEGAL | FSRTL_WILD_CHARACTER,                                     /* `*',    0x2a */
    FSRTL_OLE_LEGAL | FSRTL_HPFS_LEGAL | FSRTL_NTFS_LEGAL,                      /* `+',    0x2b */
    FSRTL_OLE_LEGAL | FSRTL_HPFS_LEGAL | FSRTL_NTFS_LEGAL,                      /* `,',    0x2c */
    FSRTL_OLE_LEGAL | FSRTL_FAT_LEGAL | FSRTL_HPFS_LEGAL | FSRTL_NTFS_LEGAL,    /* `-',    0x2d */
    FSRTL_FAT_LEGAL | FSRTL_HPFS_LEGAL | FSRTL_NTFS_LEGAL,                      /* `.',    0x2e */
    0,                                                                          /* `/',    0x2f */
    FSRTL_OLE_LEGAL | FSRTL_FAT_LEGAL | FSRTL_HPFS_LEGAL | FSRTL_NTFS_LEGAL,    /* `0',    0x30 */
    FSRTL_OLE_LEGAL | FSRTL_FAT_LEGAL | FSRTL_HPFS_LEGAL | FSRTL_NTFS_LEGAL,    /* `1',    0x31 */
    FSRTL_OLE_LEGAL | FSRTL_FAT_LEGAL | FSRTL_HPFS_LEGAL | FSRTL_NTFS_LEGAL,    /* `2',    0x32 */
    FSRTL_OLE_LEGAL | FSRTL_FAT_LEGAL | FSRTL_HPFS_LEGAL | FSRTL_NTFS_LEGAL,    /* `3',    0x33 */
    FSRTL_OLE_LEGAL | FSRTL_FAT_LEGAL | FSRTL_HPFS_LEGAL | FSRTL_NTFS_LEGAL,    /* `4',    0x34 */
    FSRTL_OLE_LEGAL | FSRTL_FAT_LEGAL | FSRTL_HPFS_LEGAL | FSRTL_NTFS_LEGAL,    /* `5',    0x35 */
    FSRTL_OLE_LEGAL | FSRTL_FAT_LEGAL | FSRTL_HPFS_LEGAL | FSRTL_NTFS_LEGAL,    /* `6',    0x36 */
    FSRTL_OLE_LEGAL | FSRTL_FAT_LEGAL | FSRTL_HPFS_LEGAL | FSRTL_NTFS_LEGAL,    /* `7',    0x37 */
    FSRTL_OLE_LEGAL | FSRTL_FAT_LEGAL | FSRTL_HPFS_LEGAL | FSRTL_NTFS_LEGAL,    /* `8',    0x38 */
    FSRTL_OLE_LEGAL | FSRTL_FAT_LEGAL | FSRTL_HPFS_LEGAL | FSRTL_NTFS_LEGAL,    /* `9',    0x39 */
    FSRTL_NTFS_LEGAL,                                                           /* `:',    0x3a */
    FSRTL_OLE_LEGAL | FSRTL_HPFS_LEGAL | FSRTL_NTFS_LEGAL,                      /* `;',    0x3b */
    FSRTL_OLE_LEGAL | FSRTL_WILD_CHARACTER,                                     /* `<',    0x3c */
    FSRTL_OLE_LEGAL | FSRTL_HPFS_LEGAL | FSRTL_NTFS_LEGAL,                      /* `=',    0x3d */
    FSRTL_OLE_LEGAL | FSRTL_WILD_CHARACTER,                                     /* `>',    0x3e */
    FSRTL_OLE_LEGAL | FSRTL_WILD_CHARACTER,                                     /* `?',    0x3f */
    FSRTL_OLE_LEGAL | FSRTL_FAT_LEGAL | FSRTL_HPFS_LEGAL | FSRTL_NTFS_LEGAL,    /* `@',    0x40 */
    FSRTL_OLE_LEGAL | FSRTL_FAT_LEGAL | FSRTL_HPFS_LEGAL | FSRTL_NTFS_LEGAL,    /* `A',    0x41 */
    FSRTL_OLE_LEGAL | FSRTL_FAT_LEGAL | FSRTL_HPFS_LEGAL | FSRTL_NTFS_LEGAL,    /* `B',    0x42 */
    FSRTL_OLE_LEGAL | FSRTL_FAT_LEGAL | FSRTL_HPFS_LEGAL | FSRTL_NTFS_LEGAL,    /* `C',    0x43 */
    FSRTL_OLE_LEGAL | FSRTL_FAT_LEGAL | FSRTL_HPFS_LEGAL | FSRTL_NTFS_LEGAL,    /* `D',    0x44 */
    FSRTL_OLE_LEGAL | FSRTL_FAT_LEGAL | FSRTL_HPFS_LEGAL | FSRTL_NTFS_LEGAL,    /* `E',    0x45 */
    FSRTL_OLE_LEGAL | FSRTL_FAT_LEGAL | FSRTL_HPFS_LEGAL | FSRTL_NTFS_LEGAL,    /* `F',    0x46 */
    FSRTL_OLE_LEGAL | FSRTL_FAT_LEGAL | FSRTL_HPFS_LEGAL | FSRTL_NTFS_LEGAL,    /* `G',    0x47 */
    FSRTL_OLE_LEGAL | FSRTL_FAT_LEGAL | FSRTL_HPFS_LEGAL | FSRTL_NTFS_LEGAL,    /* `H',    0x48 */
    FSRTL_OLE_LEGAL | FSRTL_FAT_LEGAL | FSRTL_HPFS_LEGAL | FSRTL_NTFS_LEGAL,    /* `I',    0x49 */
    FSRTL_OLE_LEGAL | FSRTL_FAT_LEGAL | FSRTL_HPFS_LEGAL | FSRTL_NTFS_LEGAL,    /* `J',    0x4a */
    FSRTL_OLE_LEGAL | FSRTL_FAT_LEGAL | FSRTL_HPFS_LEGAL | FSRTL_NTFS_LEGAL,    /* `K',    0x4b */
    FSRTL_OLE_LEGAL | FSRTL_FAT_LEGAL | FSRTL_HPFS_LEGAL | FSRTL_NTFS_LEGAL,    /* `L',    0x4c */
    FSRTL_OLE_LEGAL | FSRTL_FAT_LEGAL | FSRTL_HPFS_LEGAL | FSRTL_NTFS_LEGAL,    /* `M',    0x4d */
    FSRTL_OLE_LEGAL | FSRTL_FAT_LEGAL | FSRTL_HPFS_LEGAL | FSRTL_NTFS_LEGAL,    /* `N',    0x4e */
    FSRTL_OLE_LEGAL | FSRTL_FAT_LEGAL | FSRTL_HPFS_LEGAL | FSRTL_NTFS_LEGAL,    /* `O',    0x4f */
    FSRTL_OLE_LEGAL | FSRTL_FAT_LEGAL | FSRTL_HPFS_LEGAL | FSRTL_NTFS_LEGAL,    /* `P',    0x50 */
    FSRTL_OLE_LEGAL | FSRTL_FAT_LEGAL | FSRTL_HPFS_LEGAL | FSRTL_NTFS_LEGAL,    /* `Q',    0x51 */
    FSRTL_OLE_LEGAL | FSRTL_FAT_LEGAL | FSRTL_HPFS_LEGAL | FSRTL_NTFS_LEGAL,    /* `R',    0x52 */
    FSRTL_OLE_LEGAL | FSRTL_FAT_LEGAL | FSRTL_HPFS_LEGAL | FSRTL_NTFS_LEGAL,    /* `S',    0x53 */
    FSRTL_OLE_LEGAL | FSRTL_FAT_LEGAL | FSRTL_HPFS_LEGAL | FSRTL_NTFS_LEGAL,    /* `T',    0x54 */
    FSRTL_OLE_LEGAL | FSRTL_FAT_LEGAL | FSRTL_HPFS_LEGAL | FSRTL_NTFS_LEGAL,    /* `U',    0x55 */
    FSRTL_OLE_LEGAL | FSRTL_FAT_LEGAL | FSRTL_HPFS_LEGAL | FSRTL_NTFS_LEGAL,    /* `V',    0x56 */
    FSRTL_OLE_LEGAL | FSRTL_FAT_LEGAL | FSRTL_HPFS_LEGAL | FSRTL_NTFS_LEGAL,    /* `W',    0x57 */
    FSRTL_OLE_LEGAL | FSRTL_FAT_LEGAL | FSRTL_HPFS_LEGAL | FSRTL_NTFS_LEGAL,    /* `X',    0x58 */
    FSRTL_OLE_LEGAL | FSRTL_FAT_LEGAL | FSRTL_HPFS_LEGAL | FSRTL_NTFS_LEGAL,    /* `Y',    0x59 */
    FSRTL_OLE_LEGAL | FSRTL_FAT_LEGAL | FSRTL_HPFS_LEGAL | FSRTL_NTFS_LEGAL,    /* `Z',    0x5a */
    FSRTL_OLE_LEGAL | FSRTL_HPFS_LEGAL | FSRTL_NTFS_LEGAL,                      /* `[',    0x5b */
    0,                                                                          /* `\',    0x5c */
    FSRTL_OLE_LEGAL | FSRTL_HPFS_LEGAL | FSRTL_NTFS_LEGAL,                      /* `]',    0x5d */
    FSRTL_OLE_LEGAL | FSRTL_FAT_LEGAL | FSRTL_HPFS_LEGAL | FSRTL_NTFS_LEGAL,    /* `^',    0x5e */
    FSRTL_OLE_LEGAL | FSRTL_FAT_LEGAL | FSRTL_HPFS_LEGAL | FSRTL_NTFS_LEGAL,    /* `_',    0x5f */
    FSRTL_OLE_LEGAL | FSRTL_FAT_LEGAL | FSRTL_HPFS_LEGAL | FSRTL_NTFS_LEGAL,    /* ``',    0x60 */
    FSRTL_OLE_LEGAL | FSRTL_FAT_LEGAL | FSRTL_HPFS_LEGAL | FSRTL_NTFS_LEGAL,    /* `a',    0x61 */
    FSRTL_OLE_LEGAL | FSRTL_FAT_LEGAL | FSRTL_HPFS_LEGAL | FSRTL_NTFS_LEGAL,    /* `b',    0x62 */
    FSRTL_OLE_LEGAL | FSRTL_FAT_LEGAL | FSRTL_HPFS_LEGAL | FSRTL_NTFS_LEGAL,    /* `c',    0x63 */
    FSRTL_OLE_LEGAL | FSRTL_FAT_LEGAL | FSRTL_HPFS_LEGAL | FSRTL_NTFS_LEGAL,    /* `d',    0x64 */
    FSRTL_OLE_LEGAL | FSRTL_FAT_LEGAL | FSRTL_HPFS_LEGAL | FSRTL_NTFS_LEGAL,    /* `e',    0x65 */
    FSRTL_OLE_LEGAL | FSRTL_FAT_LEGAL | FSRTL_HPFS_LEGAL | FSRTL_NTFS_LEGAL,    /* `f',    0x66 */
    FSRTL_OLE_LEGAL | FSRTL_FAT_LEGAL | FSRTL_HPFS_LEGAL | FSRTL_NTFS_LEGAL,    /* `g',    0x67 */
    FSRTL_OLE_LEGAL | FSRTL_FAT_LEGAL | FSRTL_HPFS_LEGAL | FSRTL_NTFS_LEGAL,    /* `h',    0x68 */
    FSRTL_OLE_LEGAL | FSRTL_FAT_LEGAL | FSRTL_HPFS_LEGAL | FSRTL_NTFS_LEGAL,    /* `i',    0x69 */
    FSRTL_OLE_LEGAL | FSRTL_FAT_LEGAL | FSRTL_HPFS_LEGAL | FSRTL_NTFS_LEGAL,    /* `j',    0x6a */
    FSRTL_OLE_LEGAL | FSRTL_FAT_LEGAL | FSRTL_HPFS_LEGAL | FSRTL_NTFS_LEGAL,    /* `k',    0x6b */
    FSRTL_OLE_LEGAL | FSRTL_FAT_LEGAL | FSRTL_HPFS_LEGAL | FSRTL_NTFS_LEGAL,    /* `l',    0x6c */
    FSRTL_OLE_LEGAL | FSRTL_FAT_LEGAL | FSRTL_HPFS_LEGAL | FSRTL_NTFS_LEGAL,    /* `m',    0x6d */
    FSRTL_OLE_LEGAL | FSRTL_FAT_LEGAL | FSRTL_HPFS_LEGAL | FSRTL_NTFS_LEGAL,    /* `n',    0x6e */
    FSRTL_OLE_LEGAL | FSRTL_FAT_LEGAL | FSRTL_HPFS_LEGAL | FSRTL_NTFS_LEGAL,    /* `o',    0x6f */
    FSRTL_OLE_LEGAL | FSRTL_FAT_LEGAL | FSRTL_HPFS_LEGAL | FSRTL_NTFS_LEGAL,    /* `p',    0x70 */
    FSRTL_OLE_LEGAL | FSRTL_FAT_LEGAL | FSRTL_HPFS_LEGAL | FSRTL_NTFS_LEGAL,    /* `q',    0x71 */
    FSRTL_OLE_LEGAL | FSRTL_FAT_LEGAL | FSRTL_HPFS_LEGAL | FSRTL_NTFS_LEGAL,    /* `r',    0x72 */
    FSRTL_OLE_LEGAL | FSRTL_FAT_LEGAL | FSRTL_HPFS_LEGAL | FSRTL_NTFS_LEGAL,    /* `s',    0x73 */
    FSRTL_OLE_LEGAL | FSRTL_FAT_LEGAL | FSRTL_HPFS_LEGAL | FSRTL_NTFS_LEGAL,    /* `t',    0x74 */
    FSRTL_OLE_LEGAL | FSRTL_FAT_LEGAL | FSRTL_HPFS_LEGAL | FSRTL_NTFS_LEGAL,    /* `u',    0x75 */
    FSRTL_OLE_LEGAL | FSRTL_FAT_LEGAL | FSRTL_HPFS_LEGAL | FSRTL_NTFS_LEGAL,    /* `v',    0x76 */
    FSRTL_OLE_LEGAL | FSRTL_FAT_LEGAL | FSRTL_HPFS_LEGAL | FSRTL_NTFS_LEGAL,    /* `w',    0x77 */
    FSRTL_OLE_LEGAL | FSRTL_FAT_LEGAL | FSRTL_HPFS_LEGAL | FSRTL_NTFS_LEGAL,    /* `x',    0x78 */
    FSRTL_OLE_LEGAL | FSRTL_FAT_LEGAL | FSRTL_HPFS_LEGAL | FSRTL_NTFS_LEGAL,    /* `y',    0x79 */
    FSRTL_OLE_LEGAL | FSRTL_FAT_LEGAL | FSRTL_HPFS_LEGAL | FSRTL_NTFS_LEGAL,    /* `z',    0x7a */
    FSRTL_OLE_LEGAL | FSRTL_FAT_LEGAL | FSRTL_HPFS_LEGAL | FSRTL_NTFS_LEGAL,    /* `{',    0x7b */
    FSRTL_OLE_LEGAL,                                                            /* `|',    0x7c */
    FSRTL_OLE_LEGAL | FSRTL_FAT_LEGAL | FSRTL_HPFS_LEGAL | FSRTL_NTFS_LEGAL,    /* `}',    0x7d */
    FSRTL_OLE_LEGAL | FSRTL_FAT_LEGAL | FSRTL_HPFS_LEGAL | FSRTL_NTFS_LEGAL,    /* `~',    0x7e */
    FSRTL_OLE_LEGAL | FSRTL_FAT_LEGAL | FSRTL_HPFS_LEGAL | FSRTL_NTFS_LEGAL     /*         0x7f */
};

#define FsRtlIsAnsiCharacterWild(C)                                            \
    FsRtlTestAnsiCharacter((C), FALSE, FALSE, FSRTL_WILD_CHARACTER)

#define FsRtlIsAnsiCharacterLegalFat(C, WILD)                                  \
    FsRtlTestAnsiCharacter((C), TRUE, (WILD), FSRTL_FAT_LEGAL)

#define FsRtlIsAnsiCharacterLegalHpfs(C, WILD)                                 \
    FsRtlTestAnsiCharacter((C), TRUE, (WILD), FSRTL_HPFS_LEGAL)

#define FsRtlIsAnsiCharacterLegalNtfs(C, WILD)                                 \
    FsRtlTestAnsiCharacter((C), TRUE, (WILD), FSRTL_NTFS_LEGAL)

#define FsRtlIsAnsiCharacterLegalNtfsStream(C,WILD_OK)                         \
    FsRtlTestAnsiCharacter((C), TRUE, (WILD_OK), FSRTL_NTFS_STREAM_LEGAL)

#define FsRtlIsAnsiCharacterLegal(C,FLAGS)                                     \
    FsRtlTestAnsiCharacter((C), TRUE, FALSE, (FLAGS))

#define FsRtlTestAnsiCharacter(C, DEFAULT_RET, WILD_OK, FLAGS)                 \
    (((SCHAR)(C) < 0) ? DEFAULT_RET :                                          \
     FlagOn(LegalAnsiCharacterArray[(C)],                                      \
                (FLAGS) | ((WILD_OK) ? FSRTL_WILD_CHARACTER : 0)))

#define FsRtlIsLeadDbcsCharacter(DBCS_CHAR)                                    \
    ((BOOLEAN)((UCHAR)(DBCS_CHAR) < 0x80 ? FALSE :                             \
              (NLS_MB_CODE_PAGE_TAG &&                                         \
               (NLS_OEM_LEAD_BYTE_INFO[(UCHAR)(DBCS_CHAR)] != 0))))

#define FsRtlIsUnicodeCharacterWild(C)                                         \
    ((((C) >= 0x40) ? FALSE :                                                  \
    FlagOn(LegalAnsiCharacterArray[(C)], FSRTL_WILD_CHARACTER )))

/* PRIVATE FUNCTIONS *********************************************************/
static BOOLEAN FsRtlIsNameInExpressionPrivate(IN PUNICODE_STRING Expression,
					      IN PUNICODE_STRING Name,
					      IN BOOLEAN IgnoreCase,
					      IN PWCHAR UpcaseTable OPTIONAL)
{
    USHORT Offset, Position, BackTrackingPosition, OldBackTrackingPosition;
    USHORT BackTrackingBuffer[16], OldBackTrackingBuffer[16] = { 0 };
    PUSHORT BackTrackingSwap, BackTracking = BackTrackingBuffer,
	OldBackTracking = OldBackTrackingBuffer;
    ULONG BackTrackingBufferSize = RTL_NUMBER_OF(BackTrackingBuffer);
    PVOID AllocatedBuffer = NULL;
    UNICODE_STRING IntExpression;
    USHORT ExpressionPosition, NamePosition = 0, MatchingChars = 1;
    BOOLEAN EndOfName = FALSE;
    BOOLEAN Result;
    BOOLEAN DontSkipDot;
    WCHAR CompareChar;

    /* Check if we were given strings at all */
    if (!Name->Length || !Expression->Length) {
	/* Return TRUE if both strings are empty, otherwise FALSE */
	if (!Name->Length && !Expression->Length)
	    return TRUE;
	else
	    return FALSE;
    }

    /* Check for a shortcut: just one wildcard */
    if (Expression->Length == sizeof(WCHAR)) {
	if (Expression->Buffer[0] == L'*')
	    return TRUE;
    }

    ASSERT(!IgnoreCase || UpcaseTable);

    /* Another shortcut, wildcard followed by some string */
    if (Expression->Buffer[0] == L'*') {
	/* Copy Expression to our local variable */
	IntExpression = *Expression;

	/* Skip the first char */
	IntExpression.Buffer++;
	IntExpression.Length -= sizeof(WCHAR);

	/* Continue only if the rest of the expression does NOT contain
	   any more wildcards */
	if (!FsRtlDoesNameContainWildCards(&IntExpression)) {
	    /* Check for a degenerate case */
	    if (Name->Length < (Expression->Length - sizeof(WCHAR)))
		return FALSE;

	    /* Calculate position */
	    NamePosition = (Name->Length - IntExpression.Length) / sizeof(WCHAR);

	    /* Compare */
	    if (!IgnoreCase) {
		/* We can just do a byte compare */
		return RtlEqualMemory(IntExpression.Buffer,
				      Name->Buffer + NamePosition, IntExpression.Length);
	    } else {
		/* Not so easy, need to upcase and check char by char */
		for (ExpressionPosition = 0;
		     ExpressionPosition < (IntExpression.Length / sizeof(WCHAR));
		     ExpressionPosition++) {
		    /* Assert that expression is already upcased! */
		    ASSERT(IntExpression.Buffer[ExpressionPosition] ==
			   UpcaseTable[IntExpression.Buffer[ExpressionPosition]]);

		    /* Now compare upcased name char with expression */
		    if (UpcaseTable[Name->Buffer[NamePosition + ExpressionPosition]] !=
			IntExpression.Buffer[ExpressionPosition]) {
			return FALSE;
		    }
		}

		/* It matches */
		return TRUE;
	    }
	}
    }

    /* Name parsing loop */
    for (; !EndOfName; MatchingChars = BackTrackingPosition, NamePosition++) {
	/* Reset positions */
	OldBackTrackingPosition = BackTrackingPosition = 0;

	if (NamePosition >= Name->Length / sizeof(WCHAR)) {
	    EndOfName = TRUE;
	    if (MatchingChars && (OldBackTracking[MatchingChars - 1] == Expression->Length * 2))
		break;
	}

	while (MatchingChars > OldBackTrackingPosition) {
	    ExpressionPosition = (OldBackTracking[OldBackTrackingPosition++] + 1) / 2;

	    /* Expression parsing loop */
	    for (Offset = 0; ExpressionPosition < Expression->Length; Offset = sizeof(WCHAR)) {
		ExpressionPosition += Offset;

		if (ExpressionPosition == Expression->Length) {
		    BackTracking[BackTrackingPosition++] = Expression->Length * 2;
		    break;
		}

		/* If buffer too small */
		if (BackTrackingPosition > BackTrackingBufferSize - 3) {
		    /* We should only ever get here once! */
		    ASSERT(AllocatedBuffer == NULL);
		    ASSERT((BackTracking == BackTrackingBuffer)
			   || (BackTracking == OldBackTrackingBuffer));
		    ASSERT((OldBackTracking == BackTrackingBuffer)
			   || (OldBackTracking == OldBackTrackingBuffer));

		    /* Calculate buffer size */
		    BackTrackingBufferSize = Expression->Length / sizeof(WCHAR) * 2 + 1;

		    /* Allocate memory for both back-tracking buffers */
		    AllocatedBuffer =
			ExAllocatePoolWithTag(2 * BackTrackingBufferSize * sizeof(USHORT), 'nrSF');
		    if (AllocatedBuffer == NULL) {
			DPRINT1("Failed to allocate BackTracking buffer. BackTrackingBufferSize = =x%x\n",
				BackTrackingBufferSize);
			Result = FALSE;
			goto Exit;
		    }

		    /* Copy BackTracking content. Note that it can point to
		     * either BackTrackingBuffer or OldBackTrackingBuffer */
		    RtlCopyMemory(AllocatedBuffer, BackTracking,
				  RTL_NUMBER_OF(BackTrackingBuffer) * sizeof(USHORT));

		    /* Place current Backtracking is at the start of the new buffer */
		    BackTracking = AllocatedBuffer;

		    /* Copy OldBackTracking content */
		    RtlCopyMemory(&BackTracking[BackTrackingBufferSize],
				  OldBackTracking,
				  RTL_NUMBER_OF(OldBackTrackingBuffer) * sizeof(USHORT));

		    /* Place current OldBackTracking after current BackTracking in the buffer */
		    OldBackTracking = &BackTracking[BackTrackingBufferSize];
		}

		/* Basic check to test if chars are equal */
		CompareChar =
		    (NamePosition >=
		     Name->Length /
		     sizeof(WCHAR)) ? UNICODE_NULL : (IgnoreCase ? UpcaseTable[Name->
									       Buffer[NamePosition]]
						      : Name->Buffer[NamePosition]);
		if (Expression->Buffer[ExpressionPosition / sizeof(WCHAR)] == CompareChar
		    && !EndOfName) {
		    BackTracking[BackTrackingPosition++] = (ExpressionPosition + sizeof(WCHAR)) * 2;
		}
		/* Check cases that eat one char */
		else if (Expression->Buffer[ExpressionPosition / sizeof(WCHAR)] == L'?'
			 && !EndOfName) {
		    BackTracking[BackTrackingPosition++] = (ExpressionPosition + sizeof(WCHAR)) * 2;
		}
		/* Test star */
		else if (Expression->Buffer[ExpressionPosition / sizeof(WCHAR)] == L'*') {
		    BackTracking[BackTrackingPosition++] = ExpressionPosition * 2;
		    BackTracking[BackTrackingPosition++] = (ExpressionPosition * 2) + 3;
		    continue;
		}
		/* Check DOS_STAR */
		else if (Expression->Buffer[ExpressionPosition / sizeof(WCHAR)] == DOS_STAR) {
		    /* Look for last dot */
		    DontSkipDot = TRUE;
		    if (!EndOfName && Name->Buffer[NamePosition] == '.') {
			for (Position = NamePosition + 1; Position < Name->Length / sizeof(WCHAR);
			     Position++) {
			    if (Name->Buffer[Position] == L'.') {
				DontSkipDot = FALSE;
				break;
			    }
			}
		    }

		    if (EndOfName || Name->Buffer[NamePosition] != L'.' || !DontSkipDot)
			BackTracking[BackTrackingPosition++] = ExpressionPosition * 2;

		    BackTracking[BackTrackingPosition++] = (ExpressionPosition * 2) + 3;
		    continue;
		}
		/* Check DOS_DOT */
		else if (Expression->Buffer[ExpressionPosition / sizeof(WCHAR)] == DOS_DOT) {
		    if (EndOfName)
			continue;

		    if (Name->Buffer[NamePosition] == L'.')
			BackTracking[BackTrackingPosition++] =
			    (ExpressionPosition + sizeof(WCHAR)) * 2;
		}
		/* Check DOS_QM */
		else if (Expression->Buffer[ExpressionPosition / sizeof(WCHAR)] == DOS_QM) {
		    if (EndOfName || Name->Buffer[NamePosition] == L'.')
			continue;

		    BackTracking[BackTrackingPosition++] = (ExpressionPosition + sizeof(WCHAR)) * 2;
		}

		/* Leave from loop */
		break;
	    }

	    for (Position = 0;
		 MatchingChars > OldBackTrackingPosition && Position < BackTrackingPosition;
		 Position++) {
		while (MatchingChars > OldBackTrackingPosition
		       && BackTracking[Position] > OldBackTracking[OldBackTrackingPosition]) {
		    ++OldBackTrackingPosition;
		}
	    }
	}

	/* Swap pointers */
	BackTrackingSwap = BackTracking;
	BackTracking = OldBackTracking;
	OldBackTracking = BackTrackingSwap;
    }

    /* Store result value */
    Result = MatchingChars > 0 && (OldBackTracking[MatchingChars - 1] == (Expression->Length * 2));

Exit:

    /* Frees the memory if necessary */
    if (AllocatedBuffer != NULL) {
	ExFreePoolWithTag(AllocatedBuffer, 'nrSF');
    }

    return Result;
}

/* PUBLIC FUNCTIONS **********************************************************/

/*++
 * @name FsRtlAreNamesEqual
 * @implemented
 *
 * Compare two strings to check if they match
 *
 * @param Name1
 *	  First unicode string to compare
 *
 * @param Name2
 *	  Second unicode string to compare
 *
 * @param IgnoreCase
 *	  If TRUE, Case will be ignored when comparing strings
 *
 * @param UpcaseTable
 *	  Table for upcase letters. If NULL is given, system one will be used
 *
 * @return TRUE if the strings are equal
 *
 * @remarks From Bo Branten's ntifs.h v25.
 *
 *--*/
NTAPI BOOLEAN FsRtlAreNamesEqual(IN PCUNICODE_STRING Name1,
				 IN PCUNICODE_STRING Name2,
				 IN BOOLEAN IgnoreCase,
				 IN PCWCH UpcaseTable OPTIONAL)
{
    UNICODE_STRING UpcaseName1;
    UNICODE_STRING UpcaseName2;
    BOOLEAN StringsAreEqual, MemoryAllocated = FALSE;
    USHORT i;
    NTSTATUS Status;

    /* Well, first check their size */
    if (Name1->Length != Name2->Length)
	return FALSE;

    /* Check if the caller didn't give an upcase table */
    if (IgnoreCase && !(UpcaseTable)) {
	/* Upcase the string ourselves */
	Status = RtlUpcaseUnicodeString(&UpcaseName1, Name1, TRUE);
	if (!NT_SUCCESS(Status))
	    RtlRaiseStatus(Status);

	/* Upcase the second string too */
	Status = RtlUpcaseUnicodeString(&UpcaseName2, Name2, TRUE);
	if (!NT_SUCCESS(Status)) {
	    RtlFreeUnicodeString(&UpcaseName1);
	    RtlRaiseStatus(Status);
	}

	Name1 = &UpcaseName1;
	Name2 = &UpcaseName2;

	/* Make sure we go through the path below, but free the strings */
	IgnoreCase = FALSE;
	MemoryAllocated = TRUE;
    }

    /* Do a case-sensitive search */
    if (!IgnoreCase) {
	/* Use a raw memory compare */
	StringsAreEqual = RtlEqualMemory(Name1->Buffer, Name2->Buffer, Name1->Length);

	/* Check if we allocated strings */
	if (MemoryAllocated) {
	    /* Free them */
	    RtlFreeUnicodeString(&UpcaseName1);
	    RtlFreeUnicodeString(&UpcaseName2);
	}

	/* Return the equality */
	return StringsAreEqual;
    } else {
	/* Case in-sensitive search */
	for (i = 0; i < Name1->Length / sizeof(WCHAR); i++) {
	    /* Check if the character matches */
	    if (UpcaseTable[Name1->Buffer[i]] != UpcaseTable[Name2->Buffer[i]]) {
		/* Non-match found! */
		return FALSE;
	    }
	}

	/* We finished the loop so we are equal */
	return TRUE;
    }
}

/*++
 * @name FsRtlDoesNameContainWildCards
 * @implemented
 *
 * Checks if the given string contains WildCards
 *
 * @param Name
 *	  Pointer to a UNICODE_STRING containing Name to examine
 *
 * @return TRUE if Name contains wildcards, FALSE otherwise
 *
 * @remarks From Bo Branten's ntifs.h v12.
 *
 *--*/
NTAPI BOOLEAN FsRtlDoesNameContainWildCards(IN PUNICODE_STRING Name)
{
    PWCHAR Ptr;

    /* Loop through every character */
    if (Name->Length) {
	Ptr = Name->Buffer + (Name->Length / sizeof(WCHAR)) - 1;
	while ((Ptr >= Name->Buffer) && (*Ptr != L'\\')) {
	    /* Check for Wildcard */
	    if (FsRtlIsUnicodeCharacterWild(*Ptr))
		return TRUE;
	    Ptr--;
	}
    }

    /* Nothing Found */
    return FALSE;
}

/*++
 * @name FsRtlIsNameInExpression
 * @implemented
 *
 * Check if the Name string is in the Expression string.
 *
 * @param Expression
 *	  The string in which we've to find Name. It can contain wildcards.
 *	  If IgnoreCase is set to TRUE, this string MUST BE uppercase.
 *
 * @param Name
 *	  The string to find. It cannot contain wildcards
 *
 * @param IgnoreCase
 *	  If set to TRUE, case will be ignore with upcasing both strings
 *
 * @param UpcaseTable
 *	  If not NULL, and if IgnoreCase is set to TRUE, it will be used to
 *	  upcase the both strings
 *
 * @return TRUE if Name is in Expression, FALSE otherwise
 *
 * @remarks From Bo Branten's ntifs.h v12. This function should be
 *	    rewritten to avoid recursion and better wildcard handling
 *	    should be implemented (see FsRtlDoesNameContainWildCards).
 *
 *--*/
NTAPI BOOLEAN FsRtlIsNameInExpression(IN PUNICODE_STRING Expression,
				      IN PUNICODE_STRING Name,
				      IN BOOLEAN IgnoreCase,
				      IN PWCHAR UpcaseTable OPTIONAL)
{
    BOOLEAN Result;
    NTSTATUS Status;
    UNICODE_STRING IntName;

    if (IgnoreCase && !UpcaseTable) {
	Status = RtlUpcaseUnicodeString(&IntName, Name, TRUE);
	if (!NT_SUCCESS(Status)) {
	    RtlRaiseStatus(Status);
	}
	Name = &IntName;
	IgnoreCase = FALSE;
    } else {
	IntName.Buffer = NULL;
    }

    Result = FsRtlIsNameInExpressionPrivate(Expression, Name, IgnoreCase, UpcaseTable);

    if (IntName.Buffer != NULL) {
	RtlFreeUnicodeString(&IntName);
    }

    return Result;
}
