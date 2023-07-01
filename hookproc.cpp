#include <windows.h>
#include "pch.h"
#include "hookproc.h"

LRESULT CALLBACK YourHookProcedure(int nCode, WPARAM wParam, LPARAM lParam) {
    // Handle the hooked events here
    return CallNextHookEx(NULL, nCode, wParam, lParam);
}