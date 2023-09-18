#include <ntifs.h>

#define SYMLINK_NAME L"\\??\\HandleIrp"
#define DEVICE_NAME L"\\device\\HandleIrp"

PDEVICE_OBJECT pDevice;

NTSTATUS Dispatcher(PDEVICE_OBJECT pDeviceObject, PIRP pIrp)
{
    PIO_STACK_LOCATION ioStackLocation = IoGetCurrentIrpStackLocation(pIrp);
    if (pDeviceObject != pDevice)
    {
        return STATUS_UNSUCCESSFUL;
    }

    // 根據收到的 IRP 做對應的處理
    switch (ioStackLocation->MajorFunction)
    {
        case IRP_MJ_CREATE:
            DbgPrint("[HandleIrpDrv] IRP_MJ_CREATE\n");
            break;
        case IRP_MJ_CLOSE:
            DbgPrint("[HandleIrpDrv] IRP_MJ_CLOSE\n");
            break;
        default:
            break;
    }

    pIrp->IoStatus.Status = STATUS_SUCCESS;
    pIrp->IoStatus.Information = 0;
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

    return STATUS_SUCCESS;
}
