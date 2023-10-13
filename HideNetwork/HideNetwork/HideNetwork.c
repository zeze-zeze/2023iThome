﻿#include <ntddk.h>
#include <fwpmk.h>
#include <fwpsk.h>
#include <wdf.h>
#include <ntstrsafe.h>

typedef struct _FILTER_ITEM
{
    UINT32 fwps_callout_id;
    UINT32 fwpm_callout_id;
    UINT64 filter_id;

} FILTER_ITEM, *PFILTER_ITEM;

typedef struct _ITEM
{
    LIST_ENTRY link;
    FILTER_ITEM data;

} ITEM, *PITEM;

HANDLE kmfe_handle;    // kernel mode filter engine handle
PDEVICE_OBJECT wfpkm_device;
LIST_ENTRY head;
KSPIN_LOCK lock;

DEFINE_GUID(WFPKM_PROVIDER_KEY, 0x11111111, 0x2222, 0x3333, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44);

VOID InitFilterList()
{
    InitializeListHead(&head);
    KeInitializeSpinLock(&lock);
}

NTSTATUS AppendFilterItem(_In_ PFILTER_ITEM item)
{
    // 加入一個項目到儲存的 List 中
    NTSTATUS status = STATUS_SUCCESS;
    PITEM list_item = (PITEM)ExAllocatePoolWithTag(NonPagedPool, sizeof(ITEM), 'MNET');
    if (list_item)
    {
        list_item->data.filter_id = item->filter_id;
        list_item->data.fwpm_callout_id = item->fwpm_callout_id;
        list_item->data.fwps_callout_id = item->fwps_callout_id;
        ExInterlockedInsertTailList(&head, &list_item->link, &lock);

        status = STATUS_SUCCESS;
    }
    else
    {
        status = STATUS_NO_MEMORY;
    }

    return status;
}

NTSTATUS TakeFilterItem(_Out_ PFILTER_ITEM item)
{
    // 從儲存的 List 中取出一個項目
    NTSTATUS status = STATUS_SUCCESS;
    KIRQL irql;
    KeAcquireSpinLock(&lock, &irql);
    {
        if (IsListEmpty(&head) || !head.Flink)
        {
            status = STATUS_NO_DATA_DETECTED;
        }
        else
        {
            PITEM first_item = CONTAINING_RECORD(head.Flink, ITEM, link);
            *item = first_item->data;
        }
    }
    KeReleaseSpinLock(&lock, irql);

    return status;
}

NTSTATUS RemoveFilterItem(_In_ PFILTER_ITEM item)
{
    // 從儲存的 List 中刪除一個項目
    NTSTATUS status = STATUS_NOT_FOUND;
    KIRQL irql;
    KeAcquireSpinLock(&lock, &irql);
    {
        PLIST_ENTRY current_link = head.Flink;
        while (current_link != &head && current_link)
        {
            PITEM current_item = CONTAINING_RECORD(current_link, ITEM, link);

            if (current_item->data.filter_id == item->filter_id ||
                current_item->data.fwpm_callout_id == item->fwpm_callout_id ||
                current_item->data.fwps_callout_id == item->fwps_callout_id)
            {
                RemoveEntryList(current_link);
                ExFreePoolWithTag(current_item, 'MNET');
                status = STATUS_SUCCESS;
                break;
            }

            current_link = current_item->link.Flink;
        }
    }
    KeReleaseSpinLock(&lock, irql);

    return status;
}

PSTR ConvertIpv4ToString(UINT32 ipv4, PCHAR buffer, size_t buffer_size)
{
    // 把 ipv4 轉成字串
    NTSTATUS status = STATUS_SUCCESS;
    status = RtlStringCbPrintfA(buffer, buffer_size, "%u.%u.%u.%u", (ipv4 >> 24) & 0xFF, (ipv4 >> 16) & 0xFF,
                                (ipv4 >> 8) & 0xFF, ipv4 & 0xFF);
    return (NT_SUCCESS(status)) ? buffer : NULL;
}

NTSTATUS InitWfp(_In_ PDEVICE_OBJECT device_object)
{
    if (!device_object)
        return STATUS_INVALID_PARAMETER;

    NTSTATUS status = STATUS_SUCCESS;

    FWPM_PROVIDER wfpkm_provider = {0};

    // 用 FwpmEngineOpen 開啟 Filter Engine
    status = FwpmEngineOpen(NULL, RPC_C_AUTHN_DEFAULT, NULL, NULL, &kmfe_handle);

    // 加入一個 Provider
    status = FwpmTransactionBegin(kmfe_handle, 0);
    wfpkm_provider.serviceName = (wchar_t*)L"HideNetwork";
    wfpkm_provider.displayData.name = (wchar_t*)L"HideNetworkProvider";
    wfpkm_provider.displayData.description = (wchar_t*)L"The provider object for HideNetwork";
    wfpkm_provider.providerKey = WFPKM_PROVIDER_KEY;

    status = FwpmProviderAdd(kmfe_handle, &wfpkm_provider, NULL);

    // 初始化儲存 Callout ID、Filter ID 的 List
    InitFilterList();

    status = FwpmTransactionCommit(kmfe_handle);
    wfpkm_device = device_object;
    if (!NT_SUCCESS(status))
        FwpmTransactionAbort(kmfe_handle);

    return status;
}


NTSTATUS FinWfp()
{
    if (!kmfe_handle)
        return STATUS_APP_INIT_FAILURE;

    NTSTATUS status = STATUS_SUCCESS;
    FILTER_ITEM item = {0};

    // 從儲存的 List 中取得 filter id、callout id 後刪除
    status = FwpmTransactionBegin(kmfe_handle, 0);

    while (NT_SUCCESS(TakeFilterItem(&item)))
    {
        status = FwpmFilterDeleteById(kmfe_handle, item.filter_id);
        status = FwpmCalloutDeleteById(kmfe_handle, item.fwpm_callout_id);
        status = FwpsCalloutUnregisterById(item.fwps_callout_id);
        status = RemoveFilterItem(&item);
    }

    status = FwpmTransactionCommit(kmfe_handle);
    FwpmProviderDeleteByKey(kmfe_handle, &WFPKM_PROVIDER_KEY);
    FwpmEngineClose(kmfe_handle);

    if (!NT_SUCCESS(status))
        FwpmTransactionAbort(kmfe_handle);

    return status;
}

VOID WdfDriverUnload(_In_ WDFDRIVER wdfdriver)
{
    FinWfp();
}

NTSTATUS InitDevice(_In_ PDRIVER_OBJECT driver_object, _In_ PUNICODE_STRING registry_path,
                    _Outptr_ PDEVICE_OBJECT* device_object)
{
    NTSTATUS status = STATUS_SUCCESS;

    WDF_OBJECT_ATTRIBUTES attributes = {0};
    WDF_DRIVER_CONFIG config = {0};
    WDFDRIVER wdfdriver = NULL;

    UNICODE_STRING device_name, dos_device_name;
    PWDFDEVICE_INIT device_init = NULL;
    WDFDEVICE wdfdevice = NULL;
    *device_object = NULL;

    // 建立與設定 WDF Driver
    WDF_OBJECT_ATTRIBUTES_INIT(&attributes);
    attributes.EvtCleanupCallback = NULL;
    attributes.EvtDestroyCallback = NULL;

    WDF_DRIVER_CONFIG_INIT(&config, NULL);
    config.EvtDriverUnload = WdfDriverUnload;
    config.DriverInitFlags |= WdfDriverInitNonPnpDriver;

    status = WdfDriverCreate(driver_object, registry_path, WDF_NO_OBJECT_ATTRIBUTES, &config, &wdfdriver);

    // 建立 Device
    device_init = WdfControlDeviceInitAllocate(wdfdriver, &SDDL_DEVOBJ_KERNEL_ONLY);
    if (!device_init)
    {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto EXIT_OF_INIT_DEVICE;
    }

    RtlInitUnicodeString(&device_name, L"\\Device\\HideNetwork");
    status = WdfDeviceInitAssignName(device_init, &device_name);
    status = WdfDeviceCreate(&device_init, WDF_NO_OBJECT_ATTRIBUTES, &wdfdevice);
    *device_object = WdfDeviceWdmGetDeviceObject(wdfdevice);

EXIT_OF_INIT_DEVICE:
    if (!NT_SUCCESS(status) && device_init)
        WdfDeviceInitFree(device_init);
    return status;
}

VOID PrettyMemory(void* addr, int length)
{
    // 用跟 xxd 一樣的格式印出 addr 位址的記憶體內容
    for (int i = 0; i < length; i += 0x10)
    {
        char buf[1024] = {0};
        for (int j = 0; j < (0x10 > length - i ? length - i : 0x10); j += 2)
        {
            sprintf_s(buf + strlen(buf), 1024 - strlen(buf), "%02x%02x ", *(unsigned char*)((char*)addr + i + j),
                      *(unsigned char*)((char*)addr + i + j + 1));
        }
        sprintf_s(buf + strlen(buf), 1024 - strlen(buf), " ");
        for (int j = 0; j < (0x10 > length - i ? length - i : 0x10); j++)
        {
            unsigned char c = *(unsigned char*)((char*)addr + i + j);
            if (c >= 32 && c <= 126)
            {
                sprintf_s(buf + strlen(buf), 1024 - strlen(buf), "%c", c);
            }
            else
            {
                sprintf_s(buf + strlen(buf), 1024 - strlen(buf), ".");
            }
        }
        sprintf_s(buf + strlen(buf), 1024 - strlen(buf), "\n");
        DbgPrint("[HideNetwork] %s", buf);
    }
}

VOID NTAPI ClassifyFunctionRoutine(_In_ const FWPS_INCOMING_VALUES0* fixed_values,
                                   _In_ const FWPS_INCOMING_METADATA_VALUES0* meta_values, _Inout_opt_ VOID* layer_data,
                                   _In_opt_ const VOID* classify_context, _In_ const FWPS_FILTER3* filter,
                                   _In_ UINT64 flow_context, _Inout_ FWPS_CLASSIFY_OUT0* classify_out)
{
    // 預設的 actionType 是 FWP_ACTION_CONTINUE，如果後面有匹配到 ithome 字串則會改成 FWP_ACTION_BLOCK
    classify_out->actionType = FWP_ACTION_CONTINUE;

    FWPS_STREAM_CALLOUT_IO_PACKET* ioPacket = (FWPS_STREAM_CALLOUT_IO_PACKET*)layer_data;
    if (ioPacket)
    {
        // 申請一塊記憶體存放取得的封包內容
        FWPS_STREAM_DATA* streamData = ioPacket->streamData;
        PVOID buf = ExAllocatePoolZero(NonPagedPool, streamData->dataLength + 5, 'HIDE');

        if (buf)
        {
            SIZE_T copy;
            FwpsCopyStreamDataToBuffer(streamData, buf, streamData->dataLength, &copy);
            if (streamData->dataLength == copy)
            {
                // 檢查封包中有沒有包含 ithome 字串，有的話就把 actionType 改成 FWP_ACTION_BLOCK 繞過 Wireshark 偵測
                if (streamData->dataLength >= 6 && strstr(buf, "ithome"))
                {
                    classify_out->actionType = FWP_ACTION_BLOCK;
                }

                // 把封包內容印出來
                PrettyMemory(buf, streamData->dataLength);
            }
            ExFreePoolWithTag(buf, 'HIDE');
        }
    }
}

NTSTATUS NTAPI NotifyFunctionRoutine(_In_ FWPS_CALLOUT_NOTIFY_TYPE notify_type, _In_ const GUID* filter_key,
                                     _Inout_ FWPS_FILTER3* filter)
{
    return STATUS_SUCCESS;
}

VOID NTAPI FlowDeleteFunctionRoutine(_In_ UINT16 layer_id, _In_ UINT32 callout_id, _In_ UINT64 flow_context)
{
    return;
}

NTSTATUS AddCalloutToLayer(_In_ const GUID* layer_key)
{
    if (!kmfe_handle)
        return STATUS_APP_INIT_FAILURE;

    FWPS_CALLOUT fwps_callout = {0};
    FWPM_CALLOUT fwpm_callout = {0};
    FWPM_FILTER fwpm_filter = {0};

    UINT32 fwps_callout_id = 0;
    UINT32 fwpm_callout_id = 0;
    UINT64 fwpm_filter_id = 0;

    // 建立和註冊一個 Callout Object 並設定 Callback 函數
    NTSTATUS status = FwpmTransactionBegin(kmfe_handle, 0);
    fwps_callout.classifyFn = ClassifyFunctionRoutine;
    fwps_callout.notifyFn = NotifyFunctionRoutine;
    fwps_callout.flowDeleteFn = FlowDeleteFunctionRoutine;
    do
    {
        status = ExUuidCreate(&fwps_callout.calloutKey);
    } while (status == STATUS_RETRY);

    status = FwpsCalloutRegister(wfpkm_device, &fwps_callout, &fwps_callout_id);

    // 將 Callout Object 加至系統
    fwpm_callout.calloutKey = fwps_callout.calloutKey;
    fwpm_callout.displayData.name = (wchar_t*)L"HideNetworkCallout";
    fwpm_callout.displayData.description = (wchar_t*)L"The callout object for HideNetwork";
    fwpm_callout.providerKey = (GUID*)&WFPKM_PROVIDER_KEY;
    fwpm_callout.applicableLayer = *layer_key;
    status = FwpmCalloutAdd(kmfe_handle, &fwpm_callout, NULL, &fwpm_callout_id);

    // 將 filter object 加至系統
    fwpm_filter.displayData.name = (wchar_t*)L"HideNetworkFilter";
    fwpm_filter.displayData.description = (wchar_t*)L"The filter object for HideNetwork";
    fwpm_filter.layerKey = *layer_key;
    fwpm_filter.action.type = FWP_ACTION_CALLOUT_UNKNOWN;
    fwpm_filter.action.calloutKey = fwps_callout.calloutKey;

    status = FwpmFilterAdd(kmfe_handle, &fwpm_filter, NULL, &fwpm_filter_id);

    // 把 callout id、filter id 儲存在 List 中
    FILTER_ITEM wfpkm_filter_item = {0};
    wfpkm_filter_item.filter_id = fwpm_filter_id;
    wfpkm_filter_item.fwpm_callout_id = fwpm_callout_id;
    wfpkm_filter_item.fwps_callout_id = fwps_callout_id;

    status = AppendFilterItem(&wfpkm_filter_item);
    status = FwpmTransactionCommit(kmfe_handle);

    if (!NT_SUCCESS(status))
        FwpmTransactionAbort(kmfe_handle);

    return status;
}

extern NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT driver_object, _In_ PUNICODE_STRING registry_path)
{
    NTSTATUS status = STATUS_SUCCESS;
    PDEVICE_OBJECT device_object;

    // 初始化 Device
    status = InitDevice(driver_object, registry_path, &device_object);

    // 初始化 WFP 設定
    status = InitWfp(device_object);

    // 設定 WFP 的 Callout
    const GUID* layer_keys[] = {&FWPM_LAYER_STREAM_V4};
    for (size_t i = 0; i < ARRAYSIZE(layer_keys); i++)
    {
        status = AddCalloutToLayer(layer_keys[i]);
        if (!NT_SUCCESS(status))
        {
            FinWfp();
            break;
        }
    }

    return status;
}