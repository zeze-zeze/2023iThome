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
