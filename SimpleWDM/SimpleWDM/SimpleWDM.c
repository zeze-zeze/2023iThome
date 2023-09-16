#include <ntddk.h>

void DriverUnload(PDRIVER_OBJECT db)
{
    UNREFERENCED_PARAMETER(db);
}

extern NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
    UNREFERENCED_PARAMETER(DriverObject);
    UNREFERENCED_PARAMETER(RegistryPath);

    // 要設定卸載函數驅動程式才能順利卸載
    DriverObject->DriverUnload = DriverUnload;

    // 用 DbgPrint 印出 Hello World，可以在 DbgView 工具中觀察
    DbgPrint("Hello World\n");

    return STATUS_SUCCESS;
}
