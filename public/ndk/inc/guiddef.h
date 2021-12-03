/*
 * Copyright (C) 2000 Alexandre Julliard
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 */

#ifndef GUID_DEFINED
#define GUID_DEFINED

typedef struct _GUID {
#ifdef _MSC_VER
    unsigned long Data1;
#else
    unsigned int Data1;
#endif
    unsigned short Data2;
    unsigned short Data3;
    unsigned char Data4[8];
} GUID;
#endif

#ifndef FAR
#define FAR
#endif

#ifndef DECLSPEC_SELECTANY
#define DECLSPEC_SELECTANY __declspec(selectany)
#endif

#ifndef EXTERN_C
#ifdef __cplusplus
#define EXTERN_C    extern "C"
#else
#define EXTERN_C    extern
#endif
#endif

#undef DEFINE_GUID

#ifdef INITGUID
#ifdef __cplusplus
#define DEFINE_GUID(name, l, w1, w2, b1, b2, b3, b4, b5, b6, b7, b8)	\
    EXTERN_C const GUID DECLSPEC_SELECTANY name =			\
    { l, w1, w2, { b1, b2,  b3,  b4,  b5,  b6,  b7,  b8 } }
#else
#define DEFINE_GUID(name, l, w1, w2, b1, b2, b3, b4, b5, b6, b7, b8)	\
    const GUID DECLSPEC_SELECTANY name =				\
    { l, w1, w2, { b1, b2,  b3,  b4,  b5,  b6,  b7,  b8 } }
#endif
#else
#if __GNUC__ >= 8
#define DEFINE_GUID(name, l, w1, w2, b1, b2, b3, b4, b5, b6, b7, b8)	\
    EXTERN_C const GUID DECLSPEC_SELECTANY name
#else
#define DEFINE_GUID(name, l, w1, w2, b1, b2, b3, b4, b5, b6, b7, b8)	\
    EXTERN_C const GUID name
#endif				// __GNUC__ >= 7
#endif

#define DEFINE_OLEGUID(name, l, w1, w2)			\
    DEFINE_GUID(name, l, w1, w2, 0xC0,0,0,0,0,0,0,0x46)

#ifndef _GUIDDEF_H_
#define _GUIDDEF_H_

#ifndef __LPGUID_DEFINED__
#define __LPGUID_DEFINED__
typedef GUID *LPGUID;
#endif

#ifndef __LPCGUID_DEFINED__
#define __LPCGUID_DEFINED__
typedef const GUID *LPCGUID;
#endif

#ifndef __IID_DEFINED__
#define __IID_DEFINED__

typedef GUID IID, *LPIID;
typedef GUID CLSID, *LPCLSID;
typedef GUID FMTID, *LPFMTID;
#define IsEqualIID(riid1, riid2) IsEqualGUID(riid1, riid2)
#define IsEqualCLSID(rclsid1, rclsid2) IsEqualGUID(rclsid1, rclsid2)
#define IsEqualFMTID(rfmtid1, rfmtid2) IsEqualGUID(rfmtid1, rfmtid2)
#define IID_NULL   GUID_NULL
#define CLSID_NULL GUID_NULL
#define FMTID_NULL GUID_NULL

#ifdef __midl_proxy
#define __MIDL_CONST
#else
#define __MIDL_CONST const
#endif

#endif				/* ndef __IID_DEFINED__ */

#ifdef __cplusplus
#define REFGUID             const GUID &
#define REFCLSID            const CLSID &
#define REFIID              const IID &
#define REFFMTID            const FMTID &
#else
#define REFGUID             const GUID* __MIDL_CONST
#define REFCLSID            const CLSID* __MIDL_CONST
#define REFIID              const IID* __MIDL_CONST
#define REFFMTID            const FMTID* __MIDL_CONST
#endif

#if !defined(__midl) && !defined(__WIDL__)
#include <string.h>
#ifdef __cplusplus

__inline int InlineIsEqualGUID(REFGUID rguid1, REFGUID rguid2)
{
    return (((unsigned long *) &rguid1)[0] ==
	    ((unsigned long *) &rguid2)[0]
	    && ((unsigned long *) &rguid1)[1] ==
	    ((unsigned long *) &rguid2)[1]
	    && ((unsigned long *) &rguid1)[2] ==
	    ((unsigned long *) &rguid2)[2]
	    && ((unsigned long *) &rguid1)[3] ==
	    ((unsigned long *) &rguid2)[3]);
}

__inline int IsEqualGUID(REFGUID rguid1, REFGUID rguid2)
{
    return !memcmp(&rguid1, &rguid2, sizeof(GUID));
}

#else

#define InlineIsEqualGUID(rguid1, rguid2)				\
    (((unsigned long *)rguid1)[0] == ((unsigned long *)rguid2)[0] &&	\
     ((unsigned long *)rguid1)[1] == ((unsigned long *)rguid2)[1] &&	\
     ((unsigned long *)rguid1)[2] == ((unsigned long *)rguid2)[2] &&	\
     ((unsigned long *)rguid1)[3] == ((unsigned long *)rguid2)[3])
#define IsEqualGUID(rguid1, rguid2) (!memcmp(rguid1, rguid2, sizeof(GUID)))

#endif
#endif				/* __midl && __WIDL__ */

#ifdef __cplusplus
#include <string.h>
#if !defined _SYS_GUID_OPERATOR_EQ_ && !defined _NO_SYS_GUID_OPERATOR_EQ_
#define _SYS_GUID_OPERATOR_EQ_
inline bool operator==(const GUID & guidOne, const GUID & guidOther)
{
    return !memcmp(&guidOne, &guidOther, sizeof(GUID));
}

inline bool operator!=(const GUID & guidOne, const GUID & guidOther)
{
    return !(guidOne == guidOther);
}
#endif
#endif

#endif				/* _GUIDDEF_H_ */
