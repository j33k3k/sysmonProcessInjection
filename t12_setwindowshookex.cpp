#include <Windows.h>
#include <stdio.h>

int main() {
    wprintf(L"[*] T12 — SetWindowsHookEx\n");

    HMODULE library = LoadLibraryA("t12_dllhook.dll");
    if (!library) {
        wprintf(L"[-] LoadLibrary failed: %lu\n", GetLastError());
        return 1;
    }
    wprintf(L"[+] dllhook.dll loaded: 0x%p\n", library);

    HOOKPROC hookProc = (HOOKPROC)GetProcAddress(library, "spotlessExport");
    if (!hookProc) {
        wprintf(L"[-] GetProcAddress failed: %lu\n", GetLastError());
        return 1;
    }
    wprintf(L"[+] spotlessExport at: 0x%p\n", hookProc);

    HHOOK hook = SetWindowsHookEx(WH_KEYBOARD, hookProc, library, 0);
    if (!hook) {
        wprintf(L"[-] SetWindowsHookEx failed: %lu\n", GetLastError());
        return 1;
    }
    wprintf(L"[+] Hook installed — press key in notepad to trigger\n");
    wprintf(L"[*] EID 7 should fire when DLL loads into notepad\n");
    wprintf(L"[*] EID 8 should NOT fire — no CreateRemoteThread\n");

    Sleep(10 * 1000);
    UnhookWindowsHookEx(hook);
    wprintf(L"[+] Hook removed\n");
    return 0;
}
