#include "pch.h"
#include <Windows.h>
#include <iostream>
#include <vector>

#define WRITE_ADDRESS_STRICTALIAS(data, addr) \
* (data + 0) = ((addr) & 0x000000ff) >> 0;   \
* (data + 1) = ((addr) & 0x0000ff00) >> 8;   \
* (data + 2) = ((addr) & 0x00ff0000) >> 16;  \
* (data + 3) = ((addr) & 0xff000000) >> 24;

__declspec(naked)  int __fastcall native_sub_405966(HINSTANCE hInstance, int nCmdShow)
{
    __asm {
        push 00405966h
        ret
    }
}

// Original function signature
typedef int(__stdcall* WinMainFunction)(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow);
WinMainFunction originalWinMainFunc = nullptr;

// Custom function that will be called instead of the original function
int __stdcall myWinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nShowCmd)
{
    OutputDebugStringA("DLL: myWinMain() func is running");
    originalWinMainFunc = reinterpret_cast<WinMainFunction>(0x0069EDC0);
    return originalWinMainFunc(hInstance, hPrevInstance, lpCmdLine, nShowCmd);
}

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

void HookFunctions() {
    writeJmp(0x00406195, myWinMain); // jmp WinMain
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
            HookFunctions();
            break;

        case DLL_PROCESS_DETACH:
            OutputDebugStringA("DLL: Detached");
            break;
    }

    return TRUE;
}