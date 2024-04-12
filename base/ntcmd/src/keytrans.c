/*
 * COPYRIGHT:       LGPL
 * PROJECT:         ReactOS text-mode setup
 * FILE:            subsys/system/usetup/keytrans.c
 * PURPOSE:         Console support functions: keyboard translation
 * PROGRAMMER:      Tinus
 *
 * NB: Hardcoded to US keyboard
 */

/* Modified by Dmitri Arkhangelski, 2007. */

/**
 * @file keytrans.c
 * @brief Keyboard codes translation.
 * @addtogroup Keyboard
 */

#include "precomp.h"

typedef struct _SCANTOASCII {
    USHORT ScanCode;
    UCHAR Normal;
    UCHAR Shift;
} SCANTOASCII, *PSCANTOASCII;

SCANTOASCII ScanToAscii[] = {
    { 0x1e, 'a', 'A' },
    { 0x30, 'b', 'B' },
    { 0x2e, 'c', 'C' },
    { 0x20, 'd', 'D' },
    { 0x12, 'e', 'E' },
    { 0x21, 'f', 'F' },
    { 0x22, 'g', 'G' },
    { 0x23, 'h', 'H' },
    { 0x17, 'i', 'I' },
    { 0x24, 'j', 'J' },
    { 0x25, 'k', 'K' },
    { 0x26, 'l', 'L' },
    { 0x32, 'm', 'M' },
    { 0x31, 'n', 'N' },
    { 0x18, 'o', 'O' },
    { 0x19, 'p', 'P' },
    { 0x10, 'q', 'Q' },
    { 0x13, 'r', 'R' },
    { 0x1f, 's', 'S' },
    { 0x14, 't', 'T' },
    { 0x16, 'u', 'U' },
    { 0x2f, 'v', 'V' },
    { 0x11, 'w', 'W' },
    { 0x2d, 'x', 'X' },
    { 0x15, 'y', 'Y' },
    { 0x2c, 'z', 'Z' },

    { 0x02, '1', '!' },
    { 0x03, '2', '@' },
    { 0x04, '3', '#' },
    { 0x05, '4', '$' },
    { 0x06, '5', '%' },
    { 0x07, '6', '^' },
    { 0x08, '7', '&' },
    { 0x09, '8', '*' },
    { 0x0a, '9', '(' },
    { 0x0b, '0', ')' },

    { 0x29, '\'', '~' },
    { 0x0c, '-', '_' },
    { 0x0d, '=', '+' },
    { 0x1a, '[', '{' },
    { 0x1b, ']', '}' },
    { 0x2b, '\\', '|' },
    { 0x27, ';', ':' },
    { 0x28, '\'', '"' },
    { 0x33, ',', '<' },
    { 0x34, '.', '>' },
    { 0x35, '/', '?' },

    { 0x4a, '-', '-' },
    { 0x4e, '+', '+' },
    { 0x37, '*', '*' },

    { 0x39, ' ', ' ' },

    { 0x1c, '\r', '\r' },
    { 0x0e, 0x08, 0x08 },	/* backspace */

    { 0, 0, 0 }
};


static void IntUpdateControlKeyState(LPDWORD State,
				     PKEYBOARD_INPUT_DATA InputData)
{
    DWORD Value = 0;

    if (InputData->Flags & KEY_E1)	/* Only the pause key has E1 */
	return;

    if (!(InputData->Flags & KEY_E0)) {
	switch (InputData->MakeCode) {
	case 0x2a:
	case 0x36:
	    Value = SHIFT_PRESSED;
	    break;
	case 0x1d:
	    Value = LEFT_CTRL_PRESSED;
	    break;
	case 0x38:
	    Value = LEFT_ALT_PRESSED;
	    break;
	case 0x45:
	    Value = NUMLOCK_ON;
	    if (!(InputData->Flags & KEY_BREAK))
		*State ^= Value;
	    return;
	default:
	    return;
	}
    } else {
	switch (InputData->MakeCode) {
	case 0x1d:
	    Value = RIGHT_CTRL_PRESSED;
	    break;
	case 0x38:
	    Value = RIGHT_ALT_PRESSED;
	    break;
	default:
	    return;
	}
    }

    if (InputData->Flags & KEY_BREAK)
	*State &= ~Value;
    else
	*State |= Value;
}

static UCHAR IntAsciiFromInput(PKEYBOARD_INPUT_DATA InputData,
			       DWORD KeyState)
{
    UINT Counter = 0;

    while (ScanToAscii[Counter].ScanCode != 0) {
	if (ScanToAscii[Counter].ScanCode == InputData->MakeCode) {
	    if (KeyState & SHIFT_PRESSED)
		return ScanToAscii[Counter].Shift;
	    return ScanToAscii[Counter].Normal;
	}
	Counter++;
    }
    return 0;
}

/*
 * Only the bKeyDown and AsciiChar members are used in the zenwinx library.
 */
void IntTranslateKey(PKEYBOARD_INPUT_DATA InputData, KBD_RECORD * kbd_rec)
{
    static DWORD dwControlKeyState;

    kbd_rec->wVirtualScanCode = InputData->MakeCode;
    kbd_rec->bKeyDown = (InputData->Flags & KEY_BREAK) ? FALSE : TRUE;

    IntUpdateControlKeyState(&dwControlKeyState, InputData);
    kbd_rec->dwControlKeyState = dwControlKeyState;

    if (InputData->Flags & KEY_E0)
	kbd_rec->dwControlKeyState |= ENHANCED_KEY;

    kbd_rec->AsciiChar = IntAsciiFromInput(InputData, kbd_rec->dwControlKeyState);
}
