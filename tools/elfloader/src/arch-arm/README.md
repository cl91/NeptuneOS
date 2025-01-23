<!--
     Copyright 2017, DornerWorks

     SPDX-License-Identifier: GPL-2.0-only

     This data was produced by DornerWorks, Ltd. of Grand Rapids, MI, USA under
     a DARPA SBIR, Contract Number D16PC00107.

     Approved for Public Release, Distribution Unlimited.
-->

The elfloader Kconfig isn't accessable in most of the top-level Kconfigs.
Therefore, there are two ways to use the hashing algorithms:
      1. CONFIG_HASH_INSTRUCTIONS=y in your defconfig
         CONFIG_HASH_SHA (optional - remove if you want to md5 hash)
      2. Include the elf-loader's Kconfig under a new menu in your top-level Kconfig
         like this:

         menu "Tools"
           source "tools/elfloader/Kconfig"
         endmenu

Either one of these options will allow the user to select the hashing process.

Please note, this process will add boottime, as hashing a very long file tends to take some time.
