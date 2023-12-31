#include "pch.h"
#include <Windows.h>
#include <iostream>
#include <vector>
#include <afxribbonbar.h>
#include <ddraw.h>

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


//
// WIN MAIN IMPL STARTS HERE
//

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
/// DRAW BACKGROUND & MENU ITEMS IMPL STARTS
/// 
/// 


//typedef void(__fastcall* Sub_40290F)(LPCRITICAL_SECTION lpCriticalSection);
//Sub_40290F originalUnknownFunc1 = nullptr;
//
//void __fastcall thunk_FUN_005cff80(LPCRITICAL_SECTION lpCriticalSection)
//{
//    OutputDebugStringA("DLL: thunk_FUN_005cff80()");
//    originalUnknownFunc1 = reinterpret_cast<Sub_40290F>(0x005cff80);
//    originalUnknownFunc1(lpCriticalSection);
//    return;
//}
//
//typedef int(__fastcall* Sub_401AAF)(int param1);
//Sub_401AAF originalUnknownFunc2 = nullptr;
//
//int __fastcall thunk_FUN_005d08e0(int param1)
//{
//    OutputDebugStringA("DLL: thunk_FUN_005d08e0()");
//    originalUnknownFunc2 = reinterpret_cast<Sub_401AAF>(0x005d08e0);
//    return originalUnknownFunc2(param1);
//}
//
//typedef int(__fastcall* Sub_404813)(LPCRITICAL_SECTION lpCriticalSection);
//Sub_404813 originalUnknownFunc3 = nullptr;
//
//int __fastcall local_sub_404813(LPCRITICAL_SECTION lpCriticalSection)
//{
//    OutputDebugStringA("DLL: local_sub_404813()");
//    originalUnknownFunc3 = reinterpret_cast<Sub_404813>(0x005D08F0);
//    return originalUnknownFunc3(lpCriticalSection);
//}
//
//typedef void(__fastcall* Sub_402757)(LPCRITICAL_SECTION lpCriticalSection);
//Sub_402757 originalUnknownFunc4 = nullptr;
//
//void __fastcall local_sub_402757(LPCRITICAL_SECTION lpCriticalSection)
//{
//    OutputDebugStringA("DLL: local_sub_402757()");
//    originalUnknownFunc4 = reinterpret_cast<Sub_402757>(0x005D0A80);
//    originalUnknownFunc4(lpCriticalSection);
//}

// Helper method
template<typename ReturnType, typename ThisType, typename... Arguments>
__forceinline ReturnType Call_Method(const uintptr_t address, ThisType* const self, Arguments... args)
{
    return reinterpret_cast<ReturnType(__thiscall*)(ThisType*, Arguments...)>(address)(self, args...);
}

//class Unk7C0004 {
//private:
//    CRITICAL_SECTION section;
//    uint8_t pad[0x4];
//    LPDIRECTDRAW  var_1C;
//    uint8_t pad[0x440 - 0x20];
//public:
//    void sub_5CFF80();
//    int sub_5D08E0();
//    LPDIRECTDRAW getUnk1C() { return var_1C; } // 0x005D08E0
//};
//
//class Unk7C0010 {
//    uint8_t pad[0x11D4 - 0x0];
//    uint16_t var_11D4; // 0x11D4
//    uint8_t var_11D6;  // 0x11D6
//    uint8_t pad[0x1BDC - 0x11D6];
//public:
//    void drawMenuItems3(HWND param_1, char param_2) { // sub_634B20
//        OutputDebugStringA("DLL: drawMenuItems3() START");
//        //Call_Method<void, Unk7C0010, HWND, char>(0x00634B20, this, param_1, param_2);
//
//        //int v3; // eax
//        LPDIRECTDRAW v3;
//
//        Unk7C0010* v4; // ecx
//        void* v5; // eax
//        void* v6; // edi
//        int v7; // eax
//        int v8; // esi
//        void* v9; // eax
//        void* v10; // ebx
//        int v11; // eax
//        void* v12; // eax
//        void* v13; // esi
//        int v14; // eax
//        int v15; // edi
//        signed int v16; // ebx
//        int v17; // esi
//        char v18; // al
//        int result; // eax
//        //int v49; // [esp+Ch] [ebp-94h]
//        DDSURFACEDESC v49{};
//        int v50; // [esp+10h] [ebp-90h]
//        int v52; // [esp+54h] [ebp-4Ch]
//        int v53; // [esp+58h] [ebp-48h]
//        int v54; // [esp+60h] [ebp-40h]
//        void* v55; // [esp+74h] [ebp-2Ch]
//        char v56; // [esp+78h] [ebp-28h]
//        void* v57; // [esp+8Ch] [ebp-14h]
//        Unk7C0010* v58; // [esp+90h] [ebp-10h]
//        int v59; // [esp+9Ch] [ebp-4h]
//        v58 = this;
//      
//        v4 = v58 = this;
//        Unk7C0004* lpCriticalSection = reinterpret_cast<Unk7C0004*>(0x007c0004);
//        lpCriticalSection->sub_5CFF80();
//        v3 = lpCriticalSection->getUnk1C();  // CRASHES HERE
//        this->var_11D4 = 0; // v58[2282] = 0; // ERROR!
//        this->var_11D6 = 0; // ?? 16 ?
//
//        //v49.size = 108;
//        //v49.flags = DDSD_PIXELFORMAT; // look this up
//        //v49.ddckCKSrcOverlay = 32;
//        //v49.ddckCKSrcBlt = 80;
//        //v49.ddsCaps = DDSCAPS_COMPLEX;
//        DDSURFACEDESC v49{ 108,4096, 32, 80, 8 };
//
//        // IDirectDraw_EnumDisplayModes(v3,0 /*Flags*/, lpDDSurfaceDesc /* localVar */, lpContext /* this */, lpEnumModesCallback /* 0x00401492 */)
//        // IDirectDraw_EnumDisplayModes(v3, 0, &v49 /* lpDDSurfaceDesc */, this, 0x00401492);
//        (*(void(__stdcall**)(int, DWORD, int*))(*(DWORD*)v3 + 32))(v3, 0, &v49);
//
//        local_sub_404813(lpCriticalSection);
//        local_sub_402757(lpCriticalSection);
//
//        //this->drawBackground(param_1, (char*)"Graphics\\Menu\\Main Menu.bmp", 1);
//        OutputDebugStringA("DLL: drawMenuItems3() END");
//    }
//
//    void drawBackground(HWND param_2, char* param_3, int param_4) {
//        OutputDebugStringA("DLL: drawBackground() START");
//        Call_Method<void, Unk7C0010, HWND, char*, int>(0x006352F0, this, param_2, param_3, param_4);
//        OutputDebugStringA("DLL: drawBackground() END");
//    }
//};

template<typename T> void Hook_Method(uintptr_t in, T out)
{
    writeJmp(in, ((void*&)out));
}

void HookFunctions() {
    writeJmp(0x00406195, myWinMain);
    //Hook_Method(0x00406CB2, &Unk7C0010::drawMenuItems3);
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

