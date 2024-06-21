/*
 *  acpi_drivers.h  ($Revision: 32 $)
 *
 *  Copyright (C) 2001, 2002 Andy Grover <andrew.grover@intel.com>
 *  Copyright (C) 2001, 2002 Paul Diefenbaugh <paul.s.diefenbaugh@intel.com>
 *
 * ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or (at
 *  your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful, but
 *  WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License along
 *  with this program; if not, write to the Free Software Foundation, Inc.,
 *  59 Temple Place, Suite 330, Boston, MA 02111-1307 USA.
 *
 * ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 */

#ifndef __ACPI_BUSMGR_COMPONENTS_H__
#define __ACPI_BUSMGR_COMPONENTS_H__

#include "acpi_bus.h"

#define ACPI_MAX_STRING 80

/* --------------------------------------------------------------------------
                                    ACPI Bus
   -------------------------------------------------------------------------- */

#define ACPI_BUS_COMPONENT 0x00010000
#define ACPI_BUS_CLASS "system_bus"
#define ACPI_BUS_HID "ACPI_BUS"
#define ACPI_BUSMGR_COMPONENT_NAME "ACPI Bus Driver"
#define ACPI_BUS_DEVICE_NAME "System Bus"

/* --------------------------------------------------------------------------
                                  AC Adapter
   -------------------------------------------------------------------------- */

#define ACPI_AC_COMPONENT 0x00020000
#define ACPI_AC_CLASS "ac_adapter"
#define ACPI_AC_HID "ACPI0003"
#define ACPI_AC_DRIVER_NAME "ACPI AC Adapter Driver"
#define ACPI_AC_DEVICE_NAME "AC Adapter"
#define ACPI_AC_FILE_STATE "state"
#define ACPI_AC_NOTIFY_STATUS 0x80
#define ACPI_AC_STATUS_OFFLINE 0x00
#define ACPI_AC_STATUS_ONLINE 0x01
#define ACPI_AC_STATUS_UNKNOWN 0xFF

/* --------------------------------------------------------------------------
                                     Battery
   -------------------------------------------------------------------------- */

#define ACPI_BATTERY_COMPONENT 0x00040000
#define ACPI_BATTERY_CLASS "battery"
#define ACPI_BATTERY_HID "PNP0C0A"
#define ACPI_BATTERY_DRIVER_NAME "ACPI Battery Driver"
#define ACPI_BATTERY_DEVICE_NAME "Battery"
#define ACPI_BATTERY_FILE_INFO "info"
#define ACPI_BATTERY_FILE_STATUS "state"
#define ACPI_BATTERY_FILE_ALARM "alarm"
#define ACPI_BATTERY_NOTIFY_STATUS 0x80
#define ACPI_BATTERY_NOTIFY_INFO 0x81
#define ACPI_BATTERY_UNITS_WATTS "mW"
#define ACPI_BATTERY_UNITS_AMPS "mA"

/* --------------------------------------------------------------------------
                                      Button
   -------------------------------------------------------------------------- */

#define ACPI_BUTTON_COMPONENT 0x00080000
#define ACPI_BUTTON_DRIVER_NAME "ACPI Button Driver"
#define ACPI_BUTTON_CLASS "button"
#define ACPI_BUTTON_FILE_INFO "info"
#define ACPI_BUTTON_FILE_STATE "state"
#define ACPI_BUTTON_TYPE_UNKNOWN 0x00
#define ACPI_BUTTON_NOTIFY_STATUS 0x80

#define ACPI_BUTTON_SUBCLASS_POWER "power"
#define ACPI_BUTTON_HID_POWER "PNP0C0C"
#define ACPI_BUTTON_HID_POWERF "ACPI_FPB"
#define ACPI_BUTTON_DEVICE_NAME_POWER "Power Button (CM)"
#define ACPI_BUTTON_DEVICE_NAME_POWERF "Power Button (FF)"
#define ACPI_BUTTON_TYPE_POWER 0x01
#define ACPI_BUTTON_TYPE_POWERF 0x02

#define ACPI_BUTTON_SUBCLASS_SLEEP "sleep"
#define ACPI_BUTTON_HID_SLEEP "PNP0C0E"
#define ACPI_BUTTON_HID_SLEEPF "ACPI_FSB"
#define ACPI_BUTTON_DEVICE_NAME_SLEEP "Sleep Button (CM)"
#define ACPI_BUTTON_DEVICE_NAME_SLEEPF "Sleep Button (FF)"
#define ACPI_BUTTON_TYPE_SLEEP 0x03
#define ACPI_BUTTON_TYPE_SLEEPF 0x04

#define ACPI_BUTTON_SUBCLASS_LID "lid"
#define ACPI_BUTTON_HID_LID "PNP0C0D"
#define ACPI_BUTTON_DEVICE_NAME_LID "Lid Switch"
#define ACPI_BUTTON_TYPE_LID 0x05

INT AcpiButtonInit(void);
VOID AcpiButtonExit(void);

/* --------------------------------------------------------------------------
                                Embedded Controller
   -------------------------------------------------------------------------- */

#define ACPI_EC_COMPONENT 0x00100000
#define ACPI_EC_CLASS "embedded_controller"
#define ACPI_EC_HID "PNP0C09"
#define ACPI_EC_DRIVER_NAME "ACPI Embedded Controller Driver"
#define ACPI_EC_DEVICE_NAME "Embedded Controller"
#define ACPI_EC_FILE_INFO "info"

/* --------------------------------------------------------------------------
                                       Fan
   -------------------------------------------------------------------------- */

#define ACPI_FAN_COMPONENT 0x00200000
#define ACPI_FAN_CLASS "fan"
#define ACPI_FAN_HID "PNP0C0B"
#define ACPI_FAN_DRIVER_NAME "ACPI Fan Driver"
#define ACPI_FAN_DEVICE_NAME "Fan"
#define ACPI_FAN_FILE_STATE "state"
#define ACPI_FAN_NOTIFY_STATUS 0x80

/* --------------------------------------------------------------------------
                                  Power Resource
   -------------------------------------------------------------------------- */

#define ACPI_POWER_COMPONENT 0x00800000
#define ACPI_POWER_CLASS "power_resource"
#define ACPI_POWER_HID "ACPI_PWR"
#define ACPI_POWER_DRIVER_NAME "ACPI Power Resource Driver"
#define ACPI_POWER_DEVICE_NAME "Power Resource"
#define ACPI_POWER_FILE_INFO "info"
#define ACPI_POWER_FILE_STATUS "state"
#define ACPI_POWER_RESOURCE_STATE_OFF 0x00
#define ACPI_POWER_RESOURCE_STATE_ON 0x01
#define ACPI_POWER_RESOURCE_STATE_UNKNOWN 0xFF

INT AcpiPowerGetInferredState(PACPI_DEVICE Device);
INT AcpiPowerTransition(PACPI_DEVICE Device, INT State);
INT AcpiPowerInit(void);
VOID AcpiPowerExit(void);

/* --------------------------------------------------------------------------
                                    Processor
   -------------------------------------------------------------------------- */

#define ACPI_PROCESSOR_COMPONENT 0x01000000
#define ACPI_PROCESSOR_CLASS "processor"
#define ACPI_PROCESSOR_HID "Processor"
#define ACPI_PROCESSOR_DRIVER_NAME "ACPI Processor Driver"
#define ACPI_PROCESSOR_DEVICE_NAME "Processor"
#define ACPI_PROCESSOR_FILE_INFO "info"
#define ACPI_PROCESSOR_FILE_POWER "power"
#define ACPI_PROCESSOR_FILE_PERFORMANCE "performance"
#define ACPI_PROCESSOR_FILE_THROTTLING "throttling"
#define ACPI_PROCESSOR_FILE_LIMIT "limit"
#define ACPI_PROCESSOR_NOTIFY_PERFORMANCE 0x80
#define ACPI_PROCESSOR_NOTIFY_POWER 0x81
#define ACPI_PROCESSOR_LIMIT_NONE 0x00
#define ACPI_PROCESSOR_LIMIT_INCREMENT 0x01
#define ACPI_PROCESSOR_LIMIT_DECREMENT 0x02

/* --------------------------------------------------------------------------
                                 Thermal Zone
   -------------------------------------------------------------------------- */

#define ACPI_THERMAL_COMPONENT 0x04000000
#define ACPI_THERMAL_CLASS "thermal_zone"
#define ACPI_THERMAL_HID "ThermalZone"
#define ACPI_THERMAL_DRIVER_NAME "ACPI Thermal Zone Driver"
#define ACPI_THERMAL_DEVICE_NAME "Thermal Zone"
#define ACPI_THERMAL_FILE_STATE "state"
#define ACPI_THERMAL_FILE_TEMPERATURE "temperature"
#define ACPI_THERMAL_FILE_TRIP_POINTS "trip_points"
#define ACPI_THERMAL_FILE_COOLING_MODE "cooling_mode"
#define ACPI_THERMAL_FILE_POLLING_FREQ "polling_frequency"
#define ACPI_THERMAL_NOTIFY_TEMPERATURE 0x80
#define ACPI_THERMAL_NOTIFY_THRESHOLDS 0x81
#define ACPI_THERMAL_NOTIFY_DEVICES 0x82
#define ACPI_THERMAL_NOTIFY_CRITICAL 0xF0
#define ACPI_THERMAL_NOTIFY_HOT 0xF1
#define ACPI_THERMAL_MODE_ACTIVE 0x00
#define ACPI_THERMAL_MODE_PASSIVE 0x01
#define ACPI_THERMAL_PATH_POWEROFF "/sbin/poweroff"

/* --------------------------------------------------------------------------
                                Debug Support
   -------------------------------------------------------------------------- */

#define ACPI_DEBUG_RESTORE 0
#define ACPI_DEBUG_LOW 1
#define ACPI_DEBUG_MEDIUM 2
#define ACPI_DEBUG_HIGH 3
#define ACPI_DEBUG_DRIVERS 4

#endif /*__ACPI_BUSMGR_COMPONENTS_H__*/
