/*
 * PROJECT:         Neptune OS
 * LICENSE:         GPL - See COPYING in the top level directory
 * FILE:            public/ndk/inc/ntverp.h
 * PURPOSE:         Master Version File.
 */

//
// Windows NT Build 1.0
//
#define VER_PRODUCTBUILD                    1
#define VER_PRODUCTBUILD_QFE                0

//
// Windows NT Version 0.1
//
#define VER_PRODUCTMAJORVERSION             0
#define VER_PRODUCTMINORVERSION             1
#define VER_PRODUCTVERSION_W                (0x0001)
#define VER_PRODUCTVERSION_DW               (0x00010000 | VER_PRODUCTBUILD)

//
// Not a beta
//
#define VER_PRODUCTBETA_STR                 ""

//
// Full Product Version
//
#define VER_PRODUCTVERSION						\
    VER_PRODUCTMAJORVERSION,VER_PRODUCTMINORVERSION,VER_PRODUCTBUILD,VER_PRODUCTBUILD_QFE

//
// Padding for ANSI Version String
//
#if     (VER_PRODUCTBUILD < 10)
#define VER_BPAD "000"
#elif   (VER_PRODUCTBUILD < 100)
#define VER_BPAD "00"
#elif   (VER_PRODUCTBUILD < 1000)
#define VER_BPAD "0"
#else
#define VER_BPAD
#endif

//
// Padding for Unicode Version String
//
#if     (VER_PRODUCTBUILD < 10)
#define LVER_BPAD L"000"
#elif   (VER_PRODUCTBUILD < 100)
#define LVER_BPAD L"00"
#elif   (VER_PRODUCTBUILD < 1000)
#define LVER_BPAD L"0"
#else
#define LVER_BPAD
#endif

//
// ANSI Product Version String
//
#define VER_PRODUCTVERSION_MACRO1(mj,mn,b,q)				\
    #mj "." #mn "." VER_BPAD #b "." #q "-" GIT_HEAD_SHA_SHORT
#define VER_PRODUCTVERSION_MACRO(mj,mn,b,q)				\
    VER_PRODUCTVERSION_MACRO1(mj,mn,b,q)
#define VER_PRODUCTVERSION_STRING					\
    VER_PRODUCTVERSION_MACRO(VER_PRODUCTMAJORVERSION,			\
			     VER_PRODUCTMINORVERSION,			\
			     VER_PRODUCTBUILD,				\
			     VER_PRODUCTBUILD_QFE)

//
// Unicode Product Version String
//
#define LVER_PRODUCTVERSION_MACRO1(mj,mn,b,q,l,g)			\
    L#mj L"." L#mn L"." LVER_BPAD L#b L"." L#q L"-" l ## g
#define LVER_PRODUCTVERSION_MACRO(mj,mn,b,q,g)				\
    LVER_PRODUCTVERSION_MACRO(mj, mn, b, q, L, g)
#define LVER_PRODUCTVERSION_STRING					\
    LVER_PRODUCTVERSION_MACRO(VER_PRODUCTMAJORVERSION,			\
			      VER_PRODUCTMINORVERSION,			\
			      VER_PRODUCTBUILD,				\
			      VER_PRODUCTBUILD_QFE,			\
			      GIT_HEAD_SHA_SHORT)

//
// Debug Flag
//
#if DBG
#define VER_DEBUG                           VS_FF_DEBUG
#else
#define VER_DEBUG                           0
#endif

//
// Beta Flag
//
#if BETA
#define VER_PRERELEASE                      VS_FF_PRERELEASE
#else
#define VER_PRERELEASE                      0
#endif

//
// Internal Flag
//
#if OFFICIAL_BUILD
#define VER_PRIVATE                         0
#else
#define VER_PRIVATE                         VS_FF_PRIVATEBUILD
#endif

//
// Other Flags
//
#define VER_FILEFLAGSMASK                   VS_FFI_FILEFLAGSMASK
#define VER_FILEOS                          VOS_NT_WINDOWS32
#define VER_FILEFLAGS                       (VER_PRERELEASE |	\
                                             VER_DEBUG |	\
                                             VER_PRIVATE)
