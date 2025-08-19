// bsod_kmdf.c  -- KMDF control-device driver to trigger KeBugCheckEx (lab-only)
// Build: KMDF, x64. Target only in VMs. Test-signed or test mode.
// WARNING: This driver will call KeBugCheckEx. Use only in an isolated VM snapshot.

#include <ntddk.h>
#include <wdf.h>

#pragma warning(push)
#pragma warning(disable: 4201) // allow nameless struct/union in some headers

// ---------- Names & IOCTLs ----------
#define DEVICE_NAME       L"\\Device\\BSODLauncher"
#define SYMLINK_NAME      L"\\DosDevices\\BSODLauncher"

#define IOCTL_TRIGGER_BSOD CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_PING         CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_GET_STATUS   CTL_CODE(FILE_DEVICE_UNKNOWN, 0x803, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_ARM          CTL_CODE(FILE_DEVICE_UNKNOWN, 0x804, METHOD_BUFFERED, FILE_ANY_ACCESS)

// SDDL: Protected DACL; SYSTEM and Builtin Admins full access
// D:P(A;;GA;;;SY)(A;;GA;;;BA)
DECLARE_CONST_UNICODE_STRING(g_SddlString, L"D:P(A;;GA;;;SY)(A;;GA;;;BA)");

// ---------- Structures ----------
typedef struct _BSOD_REQUEST {
    ULONG      BugCheckCode;
    ULONG_PTR  Param1;
    ULONG_PTR  Param2;
    ULONG_PTR  Param3;
    ULONG_PTR  Param4;
} BSOD_REQUEST, * PBSOD_REQUEST;

typedef struct _ARM_REQUEST {
    ULONG64 Nonce;
} ARM_REQUEST, * PARM_REQUEST;

typedef struct _STATUS_REPLY {
    ULONG   Version;
    BOOLEAN IsArmed;
    BOOLEAN IsVM;
    ULONG   LastClientPid;
    ULONG   Reserved;
} STATUS_REPLY, * PSTATUS_REPLY;

typedef struct _DRIVER_CONTEXT {
    WDFDEVICE   ControlDevice;
    BOOLEAN     IsArmed;
    ULONG64     ArmNonce;
    LARGE_INTEGER ArmExpiry;
    ULONG       LastClientPid;
    BOOLEAN     IsVM;
    UNICODE_STRING SymLink;
} DRIVER_CONTEXT, * PDRIVER_CONTEXT;

// single global context (keeps the sample simple)
static DRIVER_CONTEXT gDriverCtx;

// ---------- Forward declarations ----------
DRIVER_INITIALIZE DriverEntry;
EVT_WDF_DRIVER_UNLOAD BsodEvtDriverUnload;
EVT_WDF_IO_QUEUE_IO_DEVICE_CONTROL BsodEvtIoDeviceControl;
EVT_WDF_DEVICE_FILE_CREATE BsodEvtDeviceFileCreate;
EVT_WDF_FILE_CLEANUP BsodEvtFileCleanup;

static BOOLEAN IsHypervisorPresent(void);
static VOID SetRelativeTimeoutMs(_Out_ PLARGE_INTEGER DueTime, ULONG Millis);
static BOOLEAN IsExpired(_In_ LARGE_INTEGER Expiry);

// ---------- Helpers ----------
static BOOLEAN
IsHypervisorPresent(void)
{
#if defined(_M_X64) || defined(_M_IX86)
    int cpuInfo[4] = { 0 };
    __cpuid(cpuInfo, 1);
    return (cpuInfo[2] & (1 << 31)) ? TRUE : FALSE;
#else
    return FALSE;
#endif
}

static VOID
SetRelativeTimeoutMs(_Out_ PLARGE_INTEGER DueTime, ULONG Millis)
{
    LONGLONG ticks = -(10 * 1000 * (LONGLONG)Millis);
    DueTime->QuadPart = ticks;
}

static BOOLEAN
IsExpired(_In_ LARGE_INTEGER Expiry)
{
    LARGE_INTEGER now;
    KeQuerySystemTimePrecise(&now);
    return (now.QuadPart >= Expiry.QuadPart);
}

// ---------- DriverEntry ----------
NTSTATUS
DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath)
{
    UNREFERENCED_PARAMETER(RegistryPath);

    NTSTATUS status;
    WDF_DRIVER_CONFIG config;
    WDF_OBJECT_ATTRIBUTES attributes;

    WDF_DRIVER_CONFIG_INIT(&config, WDF_NO_EVENT_CALLBACK); // no PnP create flow needed
    config.EvtDriverUnload = BsodEvtDriverUnload;

    WDF_OBJECT_ATTRIBUTES_INIT(&attributes);

    status = WdfDriverCreate(DriverObject, RegistryPath, &attributes, &config, WDF_NO_HANDLE);
    if (!NT_SUCCESS(status)) {
        KdPrint(("bsod_kmdf: WdfDriverCreate failed 0x%08X\n", status));
        return status;
    }

    // Initialize global context
    RtlZeroMemory(&gDriverCtx, sizeof(gDriverCtx));
    gDriverCtx.IsVM = IsHypervisorPresent();

    // Create control device init
    PWDFDEVICE_INIT devInit = WdfControlDeviceInitAllocate(WdfGetDriver(), &g_SddlString);
    if (devInit == NULL) {
        KdPrint(("bsod_kmdf: WdfControlDeviceInitAllocate failed\n"));
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    // Assign name
    UNICODE_STRING devName;
    RtlInitUnicodeString(&devName, DEVICE_NAME);
    status = WdfDeviceInitAssignName(devInit, &devName);
    if (!NT_SUCCESS(status)) {
        KdPrint(("bsod_kmdf: WdfDeviceInitAssignName failed 0x%08X\n", status));
        WdfDeviceInitFree(devInit);
        return status;
    }

    WdfDeviceInitSetIoType(devInit, WdfDeviceIoBuffered);

    // File object callbacks (so we can disarm on cleanup)
    WDF_FILEOBJECT_CONFIG fcfg;
    WDF_FILEOBJECT_CONFIG_INIT(&fcfg, BsodEvtDeviceFileCreate, WDF_NO_EVENT_CALLBACK, BsodEvtFileCleanup);
    WdfDeviceInitSetFileObjectConfig(devInit, &fcfg, WDF_NO_OBJECT_ATTRIBUTES);

    WDFDEVICE device;
    status = WdfDeviceCreate(&devInit, WDF_NO_OBJECT_ATTRIBUTES, &device);
    if (!NT_SUCCESS(status)) {
        KdPrint(("bsod_kmdf: WdfDeviceCreate failed 0x%08X\n", status));
        return status;
    }

    // Default IOCTL queue
    WDF_IO_QUEUE_CONFIG qcfg;
    WDF_IO_QUEUE_CONFIG_INIT_DEFAULT_QUEUE(&qcfg, WdfIoQueueDispatchSequential);
    qcfg.EvtIoDeviceControl = BsodEvtIoDeviceControl;

    status = WdfIoQueueCreate(device, &qcfg, WDF_NO_OBJECT_ATTRIBUTES, WDF_NO_HANDLE);
    if (!NT_SUCCESS(status)) {
        KdPrint(("bsod_kmdf: WdfIoQueueCreate failed 0x%08X\n", status));
        return status;
    }

    // Create symbolic link
    RtlInitUnicodeString(&gDriverCtx.SymLink, SYMLINK_NAME);
    status = WdfDeviceCreateSymbolicLink(device, &gDriverCtx.SymLink);
    if (!NT_SUCCESS(status)) {
        KdPrint(("bsod_kmdf: WdfDeviceCreateSymbolicLink failed 0x%08X\n", status));
        return status;
    }

    gDriverCtx.ControlDevice = device;
    gDriverCtx.IsArmed = FALSE;
    gDriverCtx.ArmNonce = 0;
    gDriverCtx.ArmExpiry.QuadPart = 0;
    gDriverCtx.LastClientPid = 0;

    WdfControlFinishInitializing(device);

    KdPrint(("bsod_kmdf: Control device ready. VM=%d Link=%wZ\n", gDriverCtx.IsVM, &gDriverCtx.SymLink));
    return STATUS_SUCCESS;
}

// Add this to your driver if needed
VOID
BsodEvtDriverUnload(_In_ WDFDRIVER Driver)
{
    UNREFERENCED_PARAMETER(Driver);

    // Disarm any pending operations
    gDriverCtx.IsArmed = FALSE;
    gDriverCtx.ArmNonce = 0;
    gDriverCtx.ArmExpiry.QuadPart = 0;

    if (gDriverCtx.ControlDevice) {
        WdfObjectDelete(gDriverCtx.ControlDevice);
        gDriverCtx.ControlDevice = NULL;
    }

    if (gDriverCtx.SymLink.Buffer) {
        IoDeleteSymbolicLink(&gDriverCtx.SymLink);
    }

    KdPrint(("bsod_kmdf: Unload complete\n"));
}
// Log opens and accept
VOID
BsodEvtDeviceFileCreate(_In_ WDFDEVICE Device, _In_ WDFREQUEST Request, _In_ WDFFILEOBJECT FileObject)
{
    UNREFERENCED_PARAMETER(Device);
    UNREFERENCED_PARAMETER(FileObject);

    ULONG pid = (ULONG)(ULONG_PTR)PsGetCurrentProcessId();
    UNREFERENCED_PARAMETER(pid);
    KdPrint(("bsod_kmdf: Open by PID=%lu\n", pid));
    WdfRequestComplete(Request, STATUS_SUCCESS);
}

// Disarm on file cleanup
VOID
BsodEvtFileCleanup(_In_ WDFFILEOBJECT FileObject)
{
    UNREFERENCED_PARAMETER(FileObject);
    gDriverCtx.IsArmed = FALSE;
    gDriverCtx.ArmNonce = 0;
    gDriverCtx.ArmExpiry.QuadPart = 0;
    KdPrint(("bsod_kmdf: Disarmed on file cleanup\n"));
}

static BOOLEAN
IsArmedAndValid(void)
{
    if (!gDriverCtx.IsArmed) return FALSE;
    if (gDriverCtx.ArmExpiry.QuadPart == 0) return FALSE;
    return !IsExpired(gDriverCtx.ArmExpiry);
}

VOID
BsodEvtIoDeviceControl(
    _In_ WDFQUEUE     Queue,
    _In_ WDFREQUEST   Request,
    _In_ size_t       OutputBufferLength,
    _In_ size_t       InputBufferLength,
    _In_ ULONG        IoControlCode
)
{
    UNREFERENCED_PARAMETER(Queue);
    UNREFERENCED_PARAMETER(OutputBufferLength);
    UNREFERENCED_PARAMETER(InputBufferLength);

    NTSTATUS status = STATUS_INVALID_DEVICE_REQUEST;
    ULONG reqPid = (ULONG)(ULONG_PTR)PsGetCurrentProcessId();

    switch (IoControlCode)
    {
    case IOCTL_PING:
        status = STATUS_SUCCESS;
        break;

    case IOCTL_GET_STATUS:
    {
        PSTATUS_REPLY out = NULL;
        size_t outSize = 0;
        status = WdfRequestRetrieveOutputBuffer(Request, sizeof(STATUS_REPLY), (PVOID*)&out, &outSize);
        if (!NT_SUCCESS(status)) break;
        if (outSize < sizeof(STATUS_REPLY)) { status = STATUS_BUFFER_TOO_SMALL; break; }

        RtlZeroMemory(out, sizeof(*out));
        out->Version = 1;
        out->IsArmed = IsArmedAndValid();
        out->IsVM = gDriverCtx.IsVM;
        out->LastClientPid = gDriverCtx.LastClientPid;

        WdfRequestSetInformation(Request, sizeof(STATUS_REPLY));
        status = STATUS_SUCCESS;
    }
    break;

    case IOCTL_ARM:
    {
#ifndef ALLOW_NON_VM
        if (!gDriverCtx.IsVM) {
            KdPrint(("bsod_kmdf: ARM refused (not in VM)\n"));
            status = STATUS_NOT_SUPPORTED;
            break;
        }
#endif
        PARM_REQUEST in = NULL;
        size_t inSize = 0;
        status = WdfRequestRetrieveInputBuffer(Request, sizeof(ARM_REQUEST), (PVOID*)&in, &inSize);
        if (!NT_SUCCESS(status)) break;
        if (inSize < sizeof(ARM_REQUEST)) { status = STATUS_BUFFER_TOO_SMALL; break; }

        gDriverCtx.ArmNonce = in->Nonce;
        gDriverCtx.IsArmed = TRUE;

        LARGE_INTEGER now;
        KeQuerySystemTimePrecise(&now);
        LARGE_INTEGER rel;
        SetRelativeTimeoutMs(&rel, 10000); // 10s window
        gDriverCtx.ArmExpiry.QuadPart = now.QuadPart - rel.QuadPart;
        gDriverCtx.LastClientPid = reqPid;
        status = STATUS_SUCCESS;
    }
    break;

    case IOCTL_TRIGGER_BSOD:
    {
        reqPid = (ULONG)(ULONG_PTR)PsGetCurrentProcessId();
        KdPrint(("bsod_kmdf: IOCTL_TRIGGER_BSOD received from PID=%lu. IsArmed=%d ArmExpiry=0x%llx\n",
            reqPid, gDriverCtx.IsArmed, gDriverCtx.ArmExpiry.QuadPart));

        // Must be armed and within the arm window.
        if (!IsArmedAndValid()) {
            KdPrint(("bsod_kmdf: TRIGGER refused - not armed or expired (IsArmed=%d)\n", gDriverCtx.IsArmed));
            status = STATUS_ACCESS_DENIED;
            break;
        }

        // Retrieve and validate input buffer once
        PBSOD_REQUEST in = NULL;
        size_t inSize = 0;
        status = WdfRequestRetrieveInputBuffer(Request, sizeof(BSOD_REQUEST), (PVOID*)&in, &inSize);
        KdPrint(("bsod_kmdf: WdfRequestRetrieveInputBuffer returned 0x%08X inSize=%Iu\n", status, inSize));
        if (!NT_SUCCESS(status)) {
            KdPrint(("bsod_kmdf: RetrieveInputBuffer failed 0x%08X\n", status));
            break;
        }
        if (inSize < sizeof(BSOD_REQUEST)) {
            KdPrint(("bsod_kmdf: Input buffer too small %Iu < %zu\n", inSize, sizeof(BSOD_REQUEST)));
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }

        // Validate payload
        if (in->BugCheckCode == 0) {
            KdPrint(("bsod_kmdf: Invalid BugCheckCode == 0\n"));
            status = STATUS_INVALID_PARAMETER;
            break;
        }

        // One-shot: consume the arm and record who triggered it
        gDriverCtx.IsArmed = FALSE;
        gDriverCtx.ArmNonce = 0;
        gDriverCtx.ArmExpiry.QuadPart = 0;
        gDriverCtx.LastClientPid = reqPid;

        KdPrint(("bsod_kmdf: Trigger accepted - calling KeBugCheckEx code=0x%08X from PID=%lu\n",
            in->BugCheckCode, reqPid));

        // Actually bugcheck — never returns
        KeBugCheckEx(in->BugCheckCode, in->Param1, in->Param2, in->Param3, in->Param4);
        return; // unreachable, but keeps compiler happy
    }
    break;


    default:
        status = STATUS_INVALID_DEVICE_REQUEST;
        break;
    }

    WdfRequestComplete(Request, status);
}

#pragma warning(pop)
