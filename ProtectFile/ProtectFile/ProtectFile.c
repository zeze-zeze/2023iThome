#include <fltKernel.h>

PFLT_FILTER gFilterHandle;

NTSTATUS ProtectFileInstanceSetup(_In_ PCFLT_RELATED_OBJECTS FltObjects, _In_ FLT_INSTANCE_SETUP_FLAGS Flags,
                                  _In_ DEVICE_TYPE VolumeDeviceType, _In_ FLT_FILESYSTEM_TYPE VolumeFilesystemType)
{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(Flags);
    UNREFERENCED_PARAMETER(VolumeDeviceType);
    UNREFERENCED_PARAMETER(VolumeFilesystemType);
    PAGED_CODE();
    return STATUS_SUCCESS;
}

NTSTATUS ProtectFileUnload(_In_ FLT_FILTER_UNLOAD_FLAGS Flags)
{
    UNREFERENCED_PARAMETER(Flags);
    PAGED_CODE();
    FltUnregisterFilter(gFilterHandle);
    return STATUS_SUCCESS;
}

FLT_PREOP_CALLBACK_STATUS ProtectFilePreOperation(_Inout_ PFLT_CALLBACK_DATA Data, _In_ PCFLT_RELATED_OBJECTS FltObjects,
                                                  _Flt_CompletionContext_Outptr_ PVOID *CompletionContext)
{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);

    // 檢查開啟 Handle 的類型是不是檔案
    if (!(FILE_DIRECTORY_FILE & (Data->Iopb->Parameters.Create.Options & 0x00FFFFFF)))
    {
        // 從 Callback 提供的 Data 取得檔案路徑
        WCHAR buffer[0x101] = {0};
        USHORT length =
            Data->Iopb->TargetFileObject->FileName.Length > 0x100 ? 0x100 : Data->Iopb->TargetFileObject->FileName.Length;
        wcsncpy(buffer, Data->Iopb->TargetFileObject->FileName.Buffer, length);

        // 比對檔案路徑中有沒有 ithome，有的話就 Access Denied
        if (wcsstr(buffer, L"ithome"))
        {
            Data->IoStatus.Status = STATUS_ACCESS_DENIED;
            return FLT_PREOP_COMPLETE;
        }
    }
    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

// 要註冊的 Callback 放在 FLT_OPERATION_REGISTRATION 結構
CONST FLT_OPERATION_REGISTRATION Callbacks[] = {{IRP_MJ_CREATE, 0, ProtectFilePreOperation, NULL}, {IRP_MJ_OPERATION_END}};

// 註冊 Minifilter 驅動程式需要的一些事件處理
CONST FLT_REGISTRATION FilterRegistration = {
    sizeof(FLT_REGISTRATION),    //  Size
    FLT_REGISTRATION_VERSION,    //  Version
    0,                           //  Flags
    NULL,                        //  Context
    Callbacks,                   //  Operation callbacks
    ProtectFileUnload,           //  MiniFilterUnload
    ProtectFileInstanceSetup,    //  InstanceSetup
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
