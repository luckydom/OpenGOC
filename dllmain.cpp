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
    OutputDebugStringA("DLL: 1st -> local_sub_405966()");
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
    OutputDebugStringA("DLL: 2nd -> local_sub_4013B6()");
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
    OutputDebugStringA("DLL: 3rd -> local_sub_403D05()");
    originalThirdRunFunc = reinterpret_cast<Sub_7653F0>(0x007653F0);
    return originalThirdRunFunc(pThis, a1);
}

__declspec(naked) CMFCRibbonBar *naked_sub_4017C6() {
    OutputDebugStringA("DLL: (declspec) 4th -> local_sub_4017C6()");
    __asm {
        push 00729700h
        ret
    }
}

//typedef CMFCRibbonBar*(Sub_729700)();
//Sub_729700 *originalFourthRunFunc = nullptr;
//
//CMFCRibbonBar *local_sub_4017C6()
//{
//    OutputDebugStringA("DLL: 4th -> local_sub_4017C6()");
//    originalFourthRunFunc = reinterpret_cast<Sub_729700*>(0x00729700);
//    return originalFourthRunFunc();
//}

// GHIDRA TRY:
__declspec(naked) void local_FUN_0072cab0() {
    //OutputDebugStringA("DLL: (declspec) 2nd? -> local_FUN_0072cab0()");
    __asm {
        push 0072cab0h
        ret
    }
}

__declspec(naked) void __stdcall local_FUN_007653f0(void *pThis, int param_1) {
    //OutputDebugStringA("DLL: (declspec) 3nd? -> local_FUN_007653f0()");
    __asm {
        push 007653f0h
        ret
    }
}

__declspec(naked) void __fastcall local_FUN_00729700(void* param_1, uint32_t param_2) { // uint32_t?
    __asm {
        push 00729700h
        ret
    }
}

// Original function signature
typedef int(__stdcall* WinMainFunction)(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow);
WinMainFunction originalWinMainFunc = nullptr;

// Custom function that will be called instead of the original function
int __stdcall myWinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nShowCmd)

{
    ATOM AVar1;
    HANDLE pvVar2;
    DWORD DVar3;
    int uVar4;
    int iVar5;
    HWND pHVar6;
    BOOL BVar7;
    void* extraout_ECX;
    void* pvVar8;
    int extraout_EDX;
    int extraout_EDX_00;
    char* pcVar9;
    char* pcVar10;
    UINT UVar11;
    tagMSG* lpMsg;
    HANDLE pvStack_70;
    tagMSG tStack_6c;
    WNDCLASSEXA WStack_50;
    _MEMORYSTATUS _Stack_20;
    char title[] = "Gangsters";

    uint32_t* local_dword_7C0008 = reinterpret_cast<uint32_t*>(0x7C0008);
    uint8_t* local_byte_8FCC10 = reinterpret_cast<uint8_t*>(0x8FCC10);

    pvVar2 = CreateFileMappingA((HANDLE)0xffffffff, (LPSECURITY_ATTRIBUTES)0x0, 2, 0, 0x20, "GangstersMap");
    if (pvVar2 == (HANDLE)0x0) {
        UVar11 = 0;
        pcVar10 = title;
        pcVar9 = (char*)"Error creating mapping";
    }
    else {
        DVar3 = GetLastError();
        if (DVar3 != 0xb7) {
            do {
                Sleep(10);
                uVar4 = ShowCursor(0);
            } while (uVar4 < 0x80000000);
            HANDLE hObject = CreateEventA((LPSECURITY_ATTRIBUTES)0x0, 0, 0, "GangEv1");
            pvStack_70 = hObject;
            DVar3 = GetCurrentProcessId();
            HANDLE hProcess = OpenProcess(0x200, 0, DVar3);
            SetPriorityClass(hProcess, 0x20);
            if (hPrevInstance == 0) {
                WStack_50.cbClsExtra = 0;
                WStack_50.cbWndExtra = 0;
                WStack_50.hInstance = hInstance;
                WStack_50.cbSize = 0x30;
                WStack_50.style = 0x1003;
                WNDPROC wProc = reinterpret_cast<WNDPROC>(0x00405e3e);
                WStack_50.lpfnWndProc = wProc; // TODO: Maybe (WNDPROC)&0x00405e3e (reference?)
                WStack_50.hIcon = LoadIconA(hInstance, (LPCSTR)0x7c);
                WStack_50.hCursor = LoadCursorA((HINSTANCE)0x0, (LPCSTR)0x7f00);
                WStack_50.hbrBackground = (HBRUSH)0x0;
                WStack_50.lpszClassName = title;
                WStack_50.lpszMenuName = (LPCSTR)0x0;
                WStack_50.hIconSm = LoadIconA(hInstance, (LPCSTR)0x7c);
                AVar1 = RegisterClassExA(&WStack_50);
                if (AVar1 == 0) {
                    return 0;
                }
            }
            HWND hWndParent = local_sub_405966(hInstance, nShowCmd);
            if (hWndParent == (HWND)0x0) {
                return 0;
            }
            _Stack_20.dwLength = 0x20;
            GlobalMemoryStatus(&_Stack_20);
            if (_Stack_20.dwAvailVirtual < 0x3200000) {
                do {
                    iVar5 = ShowCursor(1);
                    Sleep(10);
                } while (iVar5 < 0);
                UVar11 = 0x10;
                pcVar10 = (char*)"Error";
                pcVar9 = (char*)"Please check disk space, you need at least 50MB free.";
                pHVar6 = GetActiveWindow();
                MessageBoxA(pHVar6, pcVar9, pcVar10, UVar11);
                return 0;
            }
            do {
                do {
                    while (true) {
                        Sleep(10);
                        while (DVar3 = MsgWaitForMultipleObjects(1, &pvStack_70, 0, 0, 0xff), DVar3 == 0) {
                            local_FUN_0072cab0();
                        }
                        if (DVar3 == 1) break;
                        pvVar8 = local_dword_7C0008;
                        uVar4 = 0x0; //extraout_EDX;
                        if (local_dword_7C0008 != (void*)0x0) {
                            local_FUN_007653f0(local_dword_7C0008, (int)&local_byte_8FCC10);
                            pvVar8 = (void*)0x0;//extraout_ECX;
                            uVar4 = 0x0;//extraout_EDX_00;
                        }
                        local_FUN_00729700(pvVar8, uVar4);
                    }
                    BVar7 = PeekMessageA(&tStack_6c, (HWND)0x0, 0, 0, 1);
                } while (BVar7 == 0);
                do {
                    if (tStack_6c.message == 0x12) {
                        CloseHandle(hObject);
                        return tStack_6c.wParam;
                    }
                    lpMsg = &tStack_6c;
                    DWORD* local_dword_7C0024 = reinterpret_cast<DWORD*>(0x7C0024); // TODO: ??? maybe dword and not cmfcribbon
                    if (local_dword_7C0024 == 0) {
                        pHVar6 = GetActiveWindow();
                        BVar7 = IsDialogMessageA(pHVar6, lpMsg);
                        if (((BVar7 == 0) || (tStack_6c.message == 0x105)) || (tStack_6c.message == 0x104))
                            goto LAB_0069f008;
                    }
                    else {
                    LAB_0069f008:
                        TranslateMessage(&tStack_6c);
                        DispatchMessageA(&tStack_6c);
                    }
                    BVar7 = PeekMessageA(&tStack_6c, (HWND)0x0, 0, 0, 1);
                } while (BVar7 != 0);
            } while (true);
        }
        UVar11 = 0x10;
        pcVar10 = (char*)title;
        pcVar9 = (char*)"Gangsters already running.";
    }
    MessageBoxA((HWND)0x0, pcVar9, pcVar10, UVar11);
    /* WARNING: Subroutine does not return */
    ExitProcess(1);
}


void HookFunctions() {
    writeJmp(0x00406195, myWinMain); // jmp WinMain
    //writeJmp(0x00405966, local_sub_405966);
    //writeJmp(0x004013B6, local_sub_4013B6);
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