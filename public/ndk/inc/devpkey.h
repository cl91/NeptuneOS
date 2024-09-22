/*
 * Copyright (C) 2010 Maarten Lankhorst for CodeWeavers
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

#include <devpropdef.h>

/* TODO: Not all DEVPROPKEYS have been defined here */

DEFINE_DEVPROPKEY(DEVPKEY_NAME, 0xb725f130, 0x47ef, 0x101a, 0xa5, 0xf1, 0x02, 0x60, 0x8c,
		  0x9e, 0xeb, 0xac, 10);

DEFINE_DEVPROPKEY(DEVPKEY_Device_DeviceDesc, 0xa45c254e, 0xdf1c, 0x4efd, 0x80, 0x20, 0x67,
		  0xd1, 0x46, 0xa8, 0x50, 0xe0, 2);
DEFINE_DEVPROPKEY(DEVPKEY_Device_HardwareIds, 0xa45c254e, 0xdf1c, 0x4efd, 0x80, 0x20,
		  0x67, 0xd1, 0x46, 0xa8, 0x50, 0xe0, 3);
DEFINE_DEVPROPKEY(DEVPKEY_Device_CompatibleIds, 0xa45c254e, 0xdf1c, 0x4efd, 0x80, 0x20,
		  0x67, 0xd1, 0x46, 0xa8, 0x50, 0xe0, 4);
DEFINE_DEVPROPKEY(DEVPKEY_Device_Service, 0xa45c254e, 0xdf1c, 0x4efd, 0x80, 0x20, 0x67,
		  0xd1, 0x46, 0xa8, 0x50, 0xe0, 6);
DEFINE_DEVPROPKEY(DEVPKEY_Device_Class, 0xa45c254e, 0xdf1c, 0x4efd, 0x80, 0x20, 0x67,
		  0xd1, 0x46, 0xa8, 0x50, 0xe0, 9);
DEFINE_DEVPROPKEY(DEVPKEY_Device_ClassGuid, 0xa45c254e, 0xdf1c, 0x4efd, 0x80, 0x20, 0x67,
		  0xd1, 0x46, 0xa8, 0x50, 0xe0, 10);
DEFINE_DEVPROPKEY(DEVPKEY_Device_Driver, 0xa45c254e, 0xdf1c, 0x4efd, 0x80, 0x20, 0x67,
		  0xd1, 0x46, 0xa8, 0x50, 0xe0, 11);
DEFINE_DEVPROPKEY(DEVPKEY_Device_ConfigFlags, 0xa45c254e, 0xdf1c, 0x4efd, 0x80, 0x20,
		  0x67, 0xd1, 0x46, 0xa8, 0x50, 0xe0, 12);
DEFINE_DEVPROPKEY(DEVPKEY_Device_Manufacturer, 0xa45c254e, 0xdf1c, 0x4efd, 0x80, 0x20,
		  0x67, 0xd1, 0x46, 0xa8, 0x50, 0xe0, 13);
DEFINE_DEVPROPKEY(DEVPKEY_Device_FriendlyName, 0xa45c254e, 0xdf1c, 0x4efd, 0x80, 0x20,
		  0x67, 0xd1, 0x46, 0xa8, 0x50, 0xe0, 14);
DEFINE_DEVPROPKEY(DEVPKEY_Device_LocationInfo, 0xa45c254e, 0xdf1c, 0x4efd, 0x80, 0x20,
		  0x67, 0xd1, 0x46, 0xa8, 0x50, 0xe0, 15);
DEFINE_DEVPROPKEY(DEVPKEY_Device_PDOName, 0xa45c254e, 0xdf1c, 0x4efd, 0x80, 0x20, 0x67,
		  0xd1, 0x46, 0xa8, 0x50, 0xe0, 16);
DEFINE_DEVPROPKEY(DEVPKEY_Device_Capabilities, 0xa45c254e, 0xdf1c, 0x4efd, 0x80, 0x20,
		  0x67, 0xd1, 0x46, 0xa8, 0x50, 0xe0, 17);
DEFINE_DEVPROPKEY(DEVPKEY_Device_UINumber, 0xa45c254e, 0xdf1c, 0x4efd, 0x80, 0x20, 0x67,
		  0xd1, 0x46, 0xa8, 0x50, 0xe0, 18);
DEFINE_DEVPROPKEY(DEVPKEY_Device_UpperFilters, 0xa45c254e, 0xdf1c, 0x4efd, 0x80, 0x20,
		  0x67, 0xd1, 0x46, 0xa8, 0x50, 0xe0, 19);
DEFINE_DEVPROPKEY(DEVPKEY_Device_LowerFilters, 0xa45c254e, 0xdf1c, 0x4efd, 0x80, 0x20,
		  0x67, 0xd1, 0x46, 0xa8, 0x50, 0xe0, 20);
DEFINE_DEVPROPKEY(DEVPKEY_Device_BusTypeGuid, 0xa45c254e, 0xdf1c, 0x4efd, 0x80, 0x20,
		  0x67, 0xd1, 0x46, 0xa8, 0x50, 0xe0, 21);
DEFINE_DEVPROPKEY(DEVPKEY_Device_LegacyBusType, 0xa45c254e, 0xdf1c, 0x4efd, 0x80, 0x20,
		  0x67, 0xd1, 0x46, 0xa8, 0x50, 0xe0, 22);
DEFINE_DEVPROPKEY(DEVPKEY_Device_BusNumber, 0xa45c254e, 0xdf1c, 0x4efd, 0x80, 0x20, 0x67,
		  0xd1, 0x46, 0xa8, 0x50, 0xe0, 23);
DEFINE_DEVPROPKEY(DEVPKEY_Device_EnumeratorName, 0xa45c254e, 0xdf1c, 0x4efd, 0x80, 0x20,
		  0x67, 0xd1, 0x46, 0xa8, 0x50, 0xe0, 24);
DEFINE_DEVPROPKEY(DEVPKEY_Device_Security, 0xa45c254e, 0xdf1c, 0x4efd, 0x80, 0x20, 0x67,
		  0xd1, 0x46, 0xa8, 0x50, 0xe0, 25);
DEFINE_DEVPROPKEY(DEVPKEY_Device_SecuritySDS, 0xa45c254e, 0xdf1c, 0x4efd, 0x80, 0x20,
		  0x67, 0xd1, 0x46, 0xa8, 0x50, 0xe0, 26);
DEFINE_DEVPROPKEY(DEVPKEY_Device_DevType, 0xa45c254e, 0xdf1c, 0x4efd, 0x80, 0x20, 0x67,
		  0xd1, 0x46, 0xa8, 0x50, 0xe0, 27);
DEFINE_DEVPROPKEY(DEVPKEY_Device_Exclusive, 0xa45c254e, 0xdf1c, 0x4efd, 0x80, 0x20, 0x67,
		  0xd1, 0x46, 0xa8, 0x50, 0xe0, 28);
DEFINE_DEVPROPKEY(DEVPKEY_Device_Characteristics, 0xa45c254e, 0xdf1c, 0x4efd, 0x80, 0x20,
		  0x67, 0xd1, 0x46, 0xa8, 0x50, 0xe0, 29);
DEFINE_DEVPROPKEY(DEVPKEY_Device_Address, 0xa45c254e, 0xdf1c, 0x4efd, 0x80, 0x20, 0x67,
		  0xd1, 0x46, 0xa8, 0x50, 0xe0, 30);
DEFINE_DEVPROPKEY(DEVPKEY_Device_UINumberDescFormat, 0xa45c254e, 0xdf1c, 0x4efd, 0x80,
		  0x20, 0x67, 0xd1, 0x46, 0xa8, 0x50, 0xe0, 31);
DEFINE_DEVPROPKEY(DEVPKEY_Device_PowerData, 0xa45c254e, 0xdf1c, 0x4efd, 0x80, 0x20, 0x67,
		  0xd1, 0x46, 0xa8, 0x50, 0xe0, 32);
DEFINE_DEVPROPKEY(DEVPKEY_Device_RemovalPolicy, 0xa45c254e, 0xdf1c, 0x4efd, 0x80, 0x20,
		  0x67, 0xd1, 0x46, 0xa8, 0x50, 0xe0, 33);
DEFINE_DEVPROPKEY(DEVPKEY_Device_RemovalPolicyDefault, 0xa45c254e, 0xdf1c, 0x4efd, 0x80,
		  0x20, 0x67, 0xd1, 0x46, 0xa8, 0x50, 0xe0, 34);
DEFINE_DEVPROPKEY(DEVPKEY_Device_RemovalPolicyOverride, 0xa45c254e, 0xdf1c, 0x4efd, 0x80,
		  0x20, 0x67, 0xd1, 0x46, 0xa8, 0x50, 0xe0, 35);
DEFINE_DEVPROPKEY(DEVPKEY_Device_InstallState, 0xa45c254e, 0xdf1c, 0x4efd, 0x80, 0x20,
		  0x67, 0xd1, 0x46, 0xa8, 0x50, 0xe0, 36);
DEFINE_DEVPROPKEY(DEVPKEY_Device_LocationPaths, 0xa45c254e, 0xdf1c, 0x4efd, 0x80, 0x20,
		  0x67, 0xd1, 0x46, 0xa8, 0x50, 0xe0, 37);
DEFINE_DEVPROPKEY(DEVPKEY_Device_BaseContainerId, 0xa45c254e, 0xdf1c, 0x4efd, 0x80, 0x20,
		  0x67, 0xd1, 0x46, 0xa8, 0x50, 0xe0, 38);
DEFINE_DEVPROPKEY(DEVPKEY_Device_InLocalMachineContainer, 0x8c7ed206, 0x3f8a, 0x4827,
		  0xb3, 0xab, 0xae, 0x9e, 0x1f, 0xae, 0xfc, 0x6c, 4);
DEFINE_DEVPROPKEY(DEVPKEY_Device_SessionId, 0x83da6326, 0x97a6, 0x4088, 0x94, 0x53, 0xa1,
		  0x92, 0x3f, 0x57, 0x3b, 0x29, 6);

DEFINE_DEVPROPKEY(DEVPKEY_DeviceInterface_FriendlyName, 0x026e516e, 0x8b14, 0x414b, 0x83,
		  0xcd, 0x85, 0x6d, 0x6f, 0xef, 0x48, 0x22, 2);
DEFINE_DEVPROPKEY(DEVPKEY_DeviceInterface_Enabled, 0x026e516e, 0x8b14, 0x414b, 0x83, 0xcd,
		  0x85, 0x6d, 0x6f, 0xef, 0x48, 0x22, 3);
DEFINE_DEVPROPKEY(DEVPKEY_DeviceInterface_ClassGuid, 0x026e516e, 0x8b14, 0x414b, 0x83,
		  0xcd, 0x85, 0x6d, 0x6f, 0xef, 0x48, 0x22, 4);
