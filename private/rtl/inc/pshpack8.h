/*
 * PROJECT:     ReactOS PSDK Headers
 * LICENSE:     CC0-1.0 (https://spdx.org/licenses/CC0-1.0)
 * PURPOSE:     Sets structure packing alignment to 8 bytes
 * COPYRIGHT:   Copyright 2017 Colin Finck (colin@reactos.org)
 */

#if !defined(RC_INVOKED)

#if defined(_MSC_VER)
#pragma warning(disable: 4103)
#endif

#if defined(__clang__)
#pragma clang diagnostic ignored "-Wpragma-pack"
#endif

#pragma pack(push, 8)
#endif
