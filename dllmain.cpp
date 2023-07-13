#include "pch.h"
#include <Windows.h>
#include <iostream>
#include <vector>
//#include <afxribbonbar.h>

#define WRITE_ADDRESS_STRICTALIAS(data, addr) \
* (data + 0) = ((addr) & 0x000000ff) >> 0;   \
* (data + 1) = ((addr) & 0x0000ff00) >> 8;   \
* (data + 2) = ((addr) & 0x00ff0000) >> 16;  \
* (data + 3) = ((addr) & 0xff000000) >> 24;


void writeMemory(uint32_t address, const void* data, size_t size)
{
#ifdef _WIN32
    if (!WriteProcessMemory(GetCurrentProcess(), (LPVOID)address, data, size, nullptr))
    {
        throw std::runtime_error("WriteProcessMemory failed");
    }
#else
    // We own the pages with PROT_WRITE | PROT_EXEC, we can simply just memcpy the data
    std::memcpy((void*)address, data, size);
#endif // _WIN32
}

void writeJmp(uint32_t address, void* fn)
{
    uint8_t data[5] = { 0 };
    data[0] = 0xE9; // JMP

    auto addr = reinterpret_cast<uintptr_t>(fn);
    WRITE_ADDRESS_STRICTALIAS(&data[1], addr - address - 5);

    writeMemory(address, data, sizeof(data));
}

void writeNop(uint32_t address, size_t count)
{
    std::vector<uint8_t> buffer(count, 0x90);
    writeMemory(address, buffer.data(), buffer.size());
}

class CMFCRibbonBar {};

__declspec(naked) HWND __fastcall native_sub_405966(HINSTANCE hInstance, int nCmdShow)
{
    __asm {
        push 00405966h
        ret
    }
}

__declspec(naked) int __stdcall naked_sub_4059C5(uint32_t* that, int a1)
{
    __asm {
        push 004059C5h
        ret
    }
}
__declspec(naked) int __stdcall naked_sub_403D05(uint32_t* that, int a1)
{
    __asm {
        push 00403D05h
        ret
    }
}

__declspec(naked) CMFCRibbonBar* naked_sub_4017C6() {
    __asm {
        push 004017C6h
        ret
    }
}

// Original function signature
typedef int(__stdcall* Sub_402031)(HINSTANCE hinst, int a2, int a3);
Sub_402031 originalKeyboardFunc = nullptr;

int __fastcall keyboardThrower(HINSTANCE hinst, int a2, int a3)
{
    OutputDebugStringA("DLL: sub_402031() replaced with keyboardThrower()");
    return 1;
}

// Original function signature
typedef int(__stdcall* WinMainFunction)(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow);
WinMainFunction originalWinMainFunc = nullptr;

// Custom function that will be called instead of the original function
int __stdcall myWinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nShowCmd)
{
    OutputDebugStringA("DLL: myWinMain() func is running");
    DWORD v4; // eax
    HINSTANCE v5; // ebx
    int result; // eax
    HWND v7; // eax
    DWORD v8; // eax
    bool v9; // zf
    CMFCRibbonBar* v10; // eax
    HWND v11; // eax
    HANDLE pHandles; // [esp+10h] [ebp-70h]
    struct tagMSG Msg; // [esp+14h] [ebp-6Ch]
    WNDCLASSEXA v14; // [esp+30h] [ebp-50h]
    struct _MEMORYSTATUS Buffer; // [esp+60h] [ebp-20h]
    char title[] = "Gangsters";

    if (!CreateFileMappingA((HANDLE)0xFFFFFFFF, 0, 2u, 0, 0x20u, "GangstersMap"))
    {
        MessageBoxA(0, "Error creating mapping", title, 0);
    LABEL_5:
        ExitProcess(1u);
    }
    if (GetLastError() == 183)
    {
        MessageBoxA(0, "Gangsters is already running", title, 0x10u);
        goto LABEL_5;
    }
    while (ShowCursor(0) > -1)
        ;
    HANDLE hObject = CreateEventA(0, 0, 0, "GangEv1");
    pHandles = hObject;
    v4 = GetCurrentProcessId();
    HANDLE hProcess = OpenProcess(0x200u, 0, v4);
    SetPriorityClass(hProcess, 0x20u);
    if (hPrevInstance)
    {
        v5 = hInstance;
    }
    else
    {
        v14.cbClsExtra = 0;
        v14.cbWndExtra = 0;
        v5 = hInstance;
        v14.hInstance = hInstance;
        v14.cbSize = 48;
        v14.style = 4099;
        v14.lpfnWndProc = (WNDPROC)0x405E3E;
        v14.hIcon = LoadIconA(hInstance, (LPCSTR)0x7C);
        v14.hCursor = LoadCursorA(0, (LPCSTR)0x7F00);
        v14.hbrBackground = 0;
        v14.lpszClassName = title;
        v14.lpszMenuName = 0;
        v14.hIconSm = LoadIconA(hInstance, (LPCSTR)0x7C);
        if (!RegisterClassExA(&v14))
            return 0;
    }
    OutputDebugStringA("DLL: before native_sub_405966");
    //writeNop(0x72CAC0, 5);
//    writeNop(0x6941CA, 5);
    
    HWND hWndParent = native_sub_405966(v5, nShowCmd);
    OutputDebugStringA("DLL: after native_sub_405966");
    if (!hWndParent)
        return 0;
    Buffer.dwLength = 32;
    GlobalMemoryStatus(&Buffer);

    /////////
    
    if (Buffer.dwAvailVirtual >= 0x3200000)
    {
        do
        {
            while (1)
            {
            LABEL_16:
                Sleep(10);
                while (1)
                {
                    v8 = MsgWaitForMultipleObjects(1u, &pHandles, 0, 0, 0xFFu);
                    if (v8)
                        break;
                    uint32_t* u_new3 = reinterpret_cast<uint32_t*>(0x7C0008);
                    uint8_t* u_new1 = reinterpret_cast<uint8_t*>(0x8FCC10);
                    naked_sub_4059C5(u_new3, (int)&u_new1);
                }
                if (v8 == 1)
                    break;
                uint32_t* u_new2 = reinterpret_cast<uint32_t*>(0x7C0008);
                if (u_new2)
                {
                    uint8_t* u_new4 = reinterpret_cast<uint8_t*>(0x8FCC10);
                    naked_sub_403D05(u_new2, (int)&u_new4);
                }
                naked_sub_4017C6();
                //OutputDebugStringA("DLL: Went pass naked_sub_4017C6()");
            }
            v9 = PeekMessageA(&Msg, 0, 0, 0, 1u) == 0;
            CMFCRibbonBar* u_v10 = reinterpret_cast<CMFCRibbonBar*>(0x7C0024);
            v10 = u_v10;
        } while (v9);
        while (Msg.message != 18)
        {
            if (v10 || (v11 = GetActiveWindow(), !IsDialogMessageA(v11, &Msg)) || Msg.message == 261 || Msg.message == 260)
            {
                TranslateMessage(&Msg);
                DispatchMessageA(&Msg);
            }
            v9 = PeekMessageA(&Msg, 0, 0, 0, 1u) == 0;
            CMFCRibbonBar* u_v10 = reinterpret_cast<CMFCRibbonBar*>(0x7C0024);
            v10 = u_v10;
            if (v9)
                goto LABEL_16;
        }
        CloseHandle(hObject);
        result = Msg.wParam;
    }
    else
    {
        while (ShowCursor(1) < 0)
            ;
        v7 = GetActiveWindow();
        MessageBoxA(v7, "Please check disk space, you need at least 50MB free.", "Error", 0x10u);
        result = 0;
    }
    return result;
    //originalWinMainFunc = reinterpret_cast<WinMainFunction>(0x0069EDC0);
    //return originalWinMainFunc(hInstance, hPrevInstance, lpCmdLine, nShowCmd);
}


void HookFunctions() {
    writeJmp(0x00406195, myWinMain); // jmp WinMain
    writeJmp(0x00402031, keyboardThrower); // jmp WinMain
    OutputDebugStringA("DLL: All functions hooked");

    //char buffer[100];
    //sprintf_s(buffer, "func mem addr is %p ", &myWinMain);
    //OutputDebugStringA(buffer);
    //std::vector<uint8_t> opCodes = {0xC2, 0x10, 0x00};
    //writeMemory(0x0069EDC0, opCodes.data(), opCodes.size());
}

// Entry point of the DLL
BOOL APIENTRY DllMain(HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved)
{
    switch (ul_reason_for_call)
    {
        case DLL_PROCESS_ATTACH:
            OutputDebugStringA("DLL: Attached");
            //MessageBox(0, L"STOP!", 0, 0);
            HookFunctions();
            break;

        case DLL_PROCESS_DETACH:
            OutputDebugStringA("DLL: Detached");
            break;
    }

    return TRUE;
}