#include <iostream>
#include <Windows.h>

#define SymLinkName L"\\\\.\\HandleIrp"

int main(int argc, char* argv[])
{
    // CreateFile 等同於傳送 IRP_MJ_CREATE 到驅動程式
    HANDLE hDevice = CreateFile(SymLinkName, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_SYSTEM, 0);
    if (hDevice == INVALID_HANDLE_VALUE)
    {
        std::cout << "CreateFile error: " << GetLastError() << std::endl;
        return 1;
    }

    // CloseHandle 等同於傳送 IRP_MJ_CLOSE 到驅動程式
    CloseHandle(hDevice);

    return 0;
}
