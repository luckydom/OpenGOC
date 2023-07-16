#include "pch.h"
#include <Windows.h>
#include <iostream>
#include <vector>
#include <afxribbonbar.h>

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


//__declspec(naked) HWND __fastcall native_sub_405966(HINSTANCE hInstance, int nCmdShow)
//{
//    //OutputDebugStringA("DLL: native_sub_405966"); // prints but then doesn't work after
//    __asm {
//        push 00405966h
//        ret
//    }
//}

typedef HWND(__fastcall* Sub_69F0D0)(HINSTANCE hInstance, int nCmdShow);
Sub_69F0D0 originalFirstRunFunc = nullptr;

HWND __fastcall local_sub_405966(HINSTANCE hInstance, int nCmdShow) // 405966 is jmp
{
    //OutputDebugStringA("DLL: 1st -> local_sub_405966()");
    originalFirstRunFunc = reinterpret_cast<Sub_69F0D0>(0x0069F0D0);
    return originalFirstRunFunc(hInstance, nCmdShow);
}

//__declspec(naked) BOOL __fastcall naked_sub_4013B6(int a1)
//{
//    OutputDebugStringA("DLL: 1st -> naked_sub_4013B6"); // Never enters function because breaks before calling it... Can make it get called, prints ok, execution continues, but nothing happens
//    __asm {
//        push 004013B6h
//        ret
//    }
//}

typedef BOOL(__thiscall* Sub_72CAB0)(void *pThis);
Sub_72CAB0 originalSecondRunFunc = nullptr;

BOOL __fastcall local_sub_4013B6(int pThis) // 4013B6 is jmp
{
    //OutputDebugStringA("DLL: 2nd -> local_sub_4013B6()");
    originalSecondRunFunc = reinterpret_cast<Sub_72CAB0>(0x0072CAB0);
    return originalSecondRunFunc((void *)pThis);
}

//__declspec(naked) char __stdcall naked_sub_403D05(uint32_t* pThis, int a1)
//{
//    // OutputDebugStringA("DLL: naked_sub_403D05"); // doesn't work if printing uncommented
//    __asm {
//        push 00403D05h
//        ret
//    }
//}

typedef char(__thiscall* Sub_7653F0)(uint32_t* pThis, int a1);
Sub_7653F0 originalThirdRunFunc = nullptr;

char __fastcall local_sub_403D05(uint32_t* pThis, int a1)
{
    //OutputDebugStringA("DLL: 3rd -> local_sub_403D05()");
    originalThirdRunFunc = reinterpret_cast<Sub_7653F0>(0x007653F0);
    return originalThirdRunFunc(pThis, a1);
}

//__declspec(naked) CMFCRibbonBar *naked_sub_4017C6() {
//    // OutputDebugStringA("DLL: naked_sub_4017C6"); // prints ok
//    __asm {
//        push 004017C6h
//        ret
//    }
//}

/// <summary>
/// Menu items not being drawn. One of the paths:
/// sub_729700 (this below) -> sub_4090AC -> sub_72AC00 -> sub_406CB2 -> sub_634B20 -> thunk_FUN_00635480 (can only be navigated in Ghidra) -> 00635523 = "New game" str
/// </summary>
typedef CMFCRibbonBar*(Sub_729700)();
Sub_729700 *originalFourthRunFunc = nullptr;

CMFCRibbonBar *local_sub_4017C6()
{
    //OutputDebugStringA("DLL: 4th -> local_sub_4017C6()");
    originalFourthRunFunc = reinterpret_cast<Sub_729700*>(0x00729700);
    return originalFourthRunFunc();
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
    // HWND hWndParent = native_sub_405966(v5, nShowCmd);
    HWND hWndParent = local_sub_405966(v5, nShowCmd);
    OutputDebugStringA("DLL: after native_sub_405966");
    if (!hWndParent)
        return 0;
    Buffer.dwLength = 32;
    GlobalMemoryStatus(&Buffer);

    /////////

    uint8_t* local_byte_8FCC10 = reinterpret_cast<uint8_t*>(0x8FCC10);
    uint32_t* local_dword_7C0008 = reinterpret_cast<uint32_t*>(0x7C0008);
    CMFCRibbonBar* local_dword_7C0024 = reinterpret_cast<CMFCRibbonBar*>(0x7C0024);
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
                    // never gets to this point coz always breaks
                    //naked_sub_4013B6((int)&local_byte_8FCC10);
                    local_sub_4013B6((int)&local_byte_8FCC10); // never gets called in normal execution during start up & draws menu items OK (checked by debugging original exe)
                }
                if (v8 == 1)
                    break;
                if (local_dword_7C0008)
                {
                    //naked_sub_403D05(local_dword_7C0008, (int)&local_byte_8FCC10);
                    local_sub_403D05(local_dword_7C0008, (int)&local_byte_8FCC10);
                }
                //naked_sub_4017C6();
                local_sub_4017C6();
            }
            v9 = PeekMessageA(&Msg, 0, 0, 0, 1u) == 0;
           
            v10 = local_dword_7C0024;
        } while (v9);
        while (Msg.message != 18)
        {
            if (v10 || (v11 = GetActiveWindow(), !IsDialogMessageA(v11, &Msg)) || Msg.message == 261 || Msg.message == 260)
            {
                TranslateMessage(&Msg);
                DispatchMessageA(&Msg);
            }
            v9 = PeekMessageA(&Msg, 0, 0, 0, 1u) == 0;
            v10 = local_dword_7C0024;
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

///
///
/// DRAW MENU ITEMS
/// 
/// 

__declspec(naked) void __fastcall thunk_FUN_005d0030(LPCRITICAL_SECTION param_1)
{
    OutputDebugStringA("DLL: thunk_FUN_005d0030");
    __asm {
        push 005d0030h
        ret
    }
}

__declspec(naked) void __fastcall thunk_FUN_006352f0(int param_1_00, HWND param_2, char* param_3, int param_4)
{
    //OutputDebugStringA("DLL: thunk_FUN_006352f0");
    __asm {
        push 006352f0h
        ret
    }
}

void __fastcall drawMenuItems(HINSTANCE* param_1_00, int param_2)
{
    char message[63];
    sprintf_s(message, "%p", &param_1_00);
    OutputDebugStringA("DLL: drawMenuItems() (possibly red herring)");
    OutputDebugStringA(message);
    //HWND pHVar1;
    //FILE* pFVar2;
    //int iVar3;
    //long lVar4;
    //char* pcVar5;
    //BOOL unaff_EBP;
    //CHAR local_64[100];

    //if (param_2 == 0) {
    //    LPCRITICAL_SECTION DAT_007c0004 = reinterpret_cast<LPCRITICAL_SECTION>(0x007c0004);
    //    thunk_FUN_005d0030(DAT_007c0004);
    //    HWND DAT_008fcc0c = reinterpret_cast<HWND>(0x008fcc0c); // hWndParent
    //    thunk_FUN_006352f0((int)param_1_00, DAT_008fcc0c, (char*)"Graphics\\Menu\\Game Options.bmp", 0); // @ 0x006354A5
    //    InvalidateRect(DAT_008fcc0c, (RECT*)0x0, 1);
    //}
    //if (DAT_007a45c8 != 0) {
    //    thunk_FUN_00645ff0((int)param_1_00, &param_1_00[0x157]->unused, 10, 9, 0x1b2);
    //}
    //thunk_FUN_00644ce0(param_1_00, 10, 10, 0x80, 0x2d, &DAT_007b416c, 0xffffff, 0xffffffff, param_1_00[0x154])
    //    ;
    //pHVar1 = thunk_FUN_006441d0(param_1_00, 0xe0, 0x57, 0xc0, 0x18, s_New_Game_007b4174, 0, 0xe6e6e6, 0xdcdcdc
    //    , 0xa0a0a, param_1_00[0x154], 0, 0xf);
    //param_1_00[0x67c] = (HINSTANCE)pHVar1;
    //pHVar1 = thunk_FUN_006441d0(param_1_00, 0xe0, 0x7f, 0xc0, 0x18, s_Continue_Previous_Game_007b4180, 0,
    //    0xe6e6e6, 0xdcdcdc, 0xa0a0a, param_1_00[0x154], 0, 0xf);
    //param_1_00[0x67d] = (HINSTANCE)pHVar1;
    //pHVar1 = thunk_FUN_006441d0(param_1_00, 0xe0, 0xa7, 0xc0, 0x18, s_Load_Game_007b4198, 0, 0xe6e6e6,
    //    0xdcdcdc, 0xa0a0a, param_1_00[0x154], 0, 0xf);
    //param_1_00[0x67e] = (HINSTANCE)pHVar1;
    //if (param_1_00[0x40b] == (HINSTANCE)0x0) {
    //    EnableWindow((HWND)param_1_00[0x67d], 0);
    //}
    //if (param_1_00[0x40a] == (HINSTANCE)0x0) {
    //    EnableWindow((HWND)param_1_00[0x67e], 0);
    //}
    //pHVar1 = thunk_FUN_006441d0(param_1_00, 0xe0, 0xcf, 0xc0, 0x18, s_Multiplayer_Game_007b41a4, 0, 0xe6e6e6,
    //    0xdcdcdc, 0xa0a0a, param_1_00[0x154], 0, 0xf);
    //param_1_00[0x67f] = (HINSTANCE)pHVar1;
    //pHVar1 = thunk_FUN_006441d0(param_1_00, 0xe0, 0xf7, 0xc0, 0x18, s_Tutorial_007b41b8, 0, 0xe6e6e6, 0xdcdcdc
    //    , 0xa0a0a, param_1_00[0x154], 0, 0xf);
    //param_1_00[0x680] = (HINSTANCE)pHVar1;
    //pHVar1 = thunk_FUN_006441d0(param_1_00, 0xe0, 0x11f, 0xc0, 0x18, s_Hall_of_Fame_007b41c4, 0, 0xe6e6e6,
    //    0xdcdcdc, 0xa0a0a, param_1_00[0x154], 0, 0xf);
    //param_1_00[0x681] = (HINSTANCE)pHVar1;
    //pHVar1 = thunk_FUN_006441d0(param_1_00, 0xe0, 0x147, 0xc0, 0x18, s_Credits_007b41d4, 0, 0xe6e6e6, 0xdcdcdc
    //    , 0xa0a0a, param_1_00[0x154], 0, 0xf);
    //param_1_00[0x682] = (HINSTANCE)pHVar1;
    //pHVar1 = thunk_FUN_006441d0(param_1_00, 0xe0, 0x16f, 0xc0, 0x18, &DAT_007b41dc, 0, 0xe6e6e6, 0xdcdcdc,
    //    0xa0a0a, param_1_00[0x154], 0, 0xf);
    //param_1_00[0x683] = (HINSTANCE)pHVar1;
    //if (*(char*)(param_1_00 + 0x67b) == '\0') {
    //    if (param_2 == 0) {
    //        UpdateWindow(DAT_008fcc0c);
    //        *(undefined*)(param_1_00 + 0x473) = 1;
    //    }
    //    pcVar5 = (char*)0x0;
    //    pFVar2 = FID_conflict:__wfopen(s_graphics\interface\640\Lieutenan_007b42f0, &DAT_007b42ec);
    //    iVar3 = FUN_0077d1f0((int)pFVar2);
    //    lVar4 = __filelength(iVar3);
    //    if (lVar4 != 0x5d394) {
    //        pcVar5 = s_Sprite_files_have_not_been_updat_007b4324;
    //    }
    //    _fclose(pFVar2);
    //    pFVar2 = FID_conflict:__wfopen(s_graphics\interface\800\Lieutenan_007b4370, &DAT_007b436c);
    //    iVar3 = FUN_0077d1f0((int)pFVar2);
    //    lVar4 = __filelength(iVar3);
    //    if (lVar4 != 0x8ff1a) {
    //        pcVar5 = s_Sprite_files_have_not_been_updat_007b43a4;
    //    }
    //    _fclose(pFVar2);
    //    if (pcVar5 != (LPCSTR)0x0) {
    //        thunk_FUN_005cf910(DAT_007c0004);
    //        thunk_FUN_005cfd20(DAT_007c0004, (byte*)(param_1_00 + 0x14), 5);
    //        *(undefined*)(param_1_00 + 0x473) = 0;
    //        do {
    //            iVar3 = ShowCursor(1);
    //        } while (iVar3 < 0);
    //        wsprintfA(local_64, pcVar5);
    //        MessageBoxA(DAT_008fcc0c, local_64, s_ICS_Update_Error_007b43ec, 0);
    //    }
    //    param_1_00[0x279] = (HINSTANCE)0x1;
    //    return;
    //}
    //do {
    //    *(char*)&pHVar1->unused = *(char*)&pHVar1->unused + (char)pHVar1;
    //    pHVar1 = (HWND)EnableWindow(pHVar1, unaff_EBP);
    //    unaff_EBP = -0x70;
    //} while (true);
}

///
///
/// DRAW MENU ITEMS ( MAYBE THIS ONE )
/// 
/// 
// Original function signature
typedef void(__thiscall* DrawMenuItemsFunc)(DWORD pThis, HWND param_1, char param_2);
DrawMenuItemsFunc originalDrawMenuItemsFunc = nullptr;

void __fastcall drawMenuItems2(DWORD pThis, HWND param_1, char param_2)
{
    OutputDebugStringA("DLL: MAYBE THE REAL drawMenuItems()");

    //HINSTANCE* local_14 = (HINSTANCE*) 0x0019F9E0;
    //thunk_FUN_006352f0((int)local_14, param_1, (char*)"Graphics\\Menu\\Main Menu.bmp", 1);

    originalDrawMenuItemsFunc = reinterpret_cast<DrawMenuItemsFunc>(0x00634B20);
    originalDrawMenuItemsFunc(pThis, param_1, param_2);
    return;
}

void HookFunctions() {
    writeJmp(0x00406195, myWinMain);
    //writeJmp(0x00405763, drawMenuItems); 
    writeJmp(0x00406CB2, drawMenuItems2);
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