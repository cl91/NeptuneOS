nlsdump: Dumps format of NLS file such as `C:\Windows\System32\C_936.NLS`
=========================================================================

```
================================================================================
  NLS CODEPAGE (C_XXX.NLS)
================================================================================
                +---------------------------------------------------------------
        HEADER  | WORD      wSize  size in word (0x0D)
                | WORD      CodePage
                | WORD      MaxCharSize
                | BYTE[2]   DefaultChar
                | WORD      UnicodeDefaultChar
                | WORD      TransDefaultChar
                | WORD      TransUniDefaultChar
                | BYTE[12]  LeadByte
                +---------------------------------------------------------------
   MB2WC TABLE  | WORD      offset of Unicode to CP table in word
                | WORD[256] primary CP to Unicode table
                | WORD      OEM glyph table size in words
                | WORD[size] OEM to Unicode table
                | WORD      Number of DBCS LeadByte range
                | if range != 0:
                |   WORD[256] offsets
                |   WORD[num_of_leadbyte][256] sub table
                +---------------------------------------------------------------
   WC2MB TABLE  | WORD      Unknown (It seems 0x0000 for MaxCharSize==1, 0x0004 for MaxCharSize==2)
                | BYTE[65536] or WORD[65536] (depends on MaxCharSize) Unicode To CP table
                +---------------------------------------------------------------
================================================================================
```

Additional information
----------------------

This is based on `reactos/tools/create_nls`

The registry key controlling NLS settings is `HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Nls`
