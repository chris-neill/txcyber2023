# Texas Cyber Summit 2023
## Introduction
This repository contains a sample Windows driver that demonstrates two techniques.

1. Replacing named objects in the object namespace without destroying the original.
2. Adding a Volume Parameter Block (VPB) to non-disk devices to redirect device open requests. 

The solution contains two projects, an application and a driver. The driver is obviously responsible for all the heavy lifting. The application serves only to drive execution of the driver via IOCTL. The driver will not be unloadable once either IOCTL executes successfully, as the required memory cleanup to allow the system to avoid a crash is not present.

The code was developed with Visual Studio <> with the Windows 10 driver kit installed, but I do not believe it contains any code or settings that would prevent compilation and linage with newer versions.

## Debugging
The driver was written with a hard-coded breakpoint in the `DriverEntry` routine. I used this breakpoint to add multiple other software breakpoints through WinDbg and have left it in intentionally. Follow the instructions on: 
```
https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/getting-started-with-windbg--kernel-mode-
```
to setup WinDbg for kernel debugging. While the hard-coded breakpoint exists if a kernel debugger is not connected prior to starting the driver the system will crash.
