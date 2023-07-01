#pragma once
#include <windows.h>

extern "C" __declspec(dllexport) LRESULT CALLBACK YourHookProcedure(int nCode, WPARAM wParam, LPARAM lParam);