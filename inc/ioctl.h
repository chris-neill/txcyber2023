#pragma once

// Ensure that the header's contents are included only once
#ifndef __TXCYBER_PUBLIC__
#define __TXCYBER_PUBLIC__

// Device and symbolic name definitions for the driver
#define DEVICE_NAME_STRING      L"TXCYBER23"                // Name used when registering the driver
#define NTDEVICE_NAME_STRING    L"\\Device\\TXCYBER23"      // Full path in the NT namespace
#define SYMBOLIC_NAME_STRING    L"\\??\\TXCYBER23"          // Symbolic link name for user-mode access

// IOCTL definitions for the driver
// CTL_CODE macro is used to create IOCTL codes:
// Arguments are DeviceType, FunctionCode, Method, Access
#define IOCTL_HIJACK_NAME       (ULONG)CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_NEITHER, FILE_ANY_ACCESS)  // IOCTL for hijacking the device name
#define IOCTL_HIJACK_STACK      (ULONG)CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_NEITHER, FILE_ANY_ACCESS)  // IOCTL for hijacking the device stack

#endif  // __TXCYBER_PUBLIC__
