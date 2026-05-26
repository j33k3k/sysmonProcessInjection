# Process Injection with Sysmon Coverage Analysis

## Purpose
This lab documents Sysmon detection coverage across a broad spectrum of Windows process injection techniques from a defensive security
perspective. The goal is to understand what Sysmon sees, what it misses, and how to tune detection rules to cover each technique. 

**Disclaimer:** The findings and conclusions in this document are based entirely on testing performed in my own isolated lab environment. All results reflect the specific configuration of my lab setup including the Windows 11 build version, Sysmon schema version, Elastic stack version, and custom Sysmon config at the time of testing. Results may differ on other builds, configurations or environments. Furthermore, my knowledge of offensive security and Windows process injection techniques is limited.
The implementations used are based on the process injection techniques documented at [Red Team Notes (ired.team)](https://www.ired.team/offensive-security/code-injection-process-injection) and vibe coded with Claude. 


---

## Lab Setup

| Component       | Details                                          |
|-----------------|--------------------------------------------------|
| Target VM       | Windows 11 Sysmon + Elastic Agent             |
| Attacker VM     | Kali Linux                                       |
| Detection Stack | Elasticsearch + Kibana + Elastic Fleet           |
| Sysmon Config   | Olaf Hartong modular config custom tuned       |
| Focus EIDs      | EID 7, EID 8, EID 10, EID 25                    |
| Compiler        | MinGW g++ on Windows 11                          |
| Payloads        | msfvenom reverse shell windows/x64/shell_reverse_tcp |

---

## Techniques Tested

| #   | Technique                           | Target      | EID 8 | EID 10 | EID 7 | EID 25 |
|-----|-------------------------------------|-------------|-------|--------|-------|--------|
| T1  | Classic CreateRemoteThread          | notepad.exe | ✅    | ✅     | ❌    | ❌     |
| T2  | NtCreateThreadEx                    | notepad.exe | ✅    | ✅     | ❌    | ❌     |
| T3  | APC Early Bird                      | notepad.exe | ❌    | ✅     | ❌    | ❌     |
| T4  | Process Hollowing                   | notepad.exe | ❌    | ✅     | ❌    | ✅     |
| T5  | Direct Syscall                      | notepad.exe | ✅    | ✅     | ❌    | ❌     |
| T6  | DLL Injection via LoadLibraryA      | notepad.exe | ✅    | ✅     | ✅    | ❌     |
| T7  | Reflective DLL Injection            | notepad.exe | ✅    | ✅     | ❌    | ❌     |
| T8  | Thread Hijacking                    | notepad.exe | ❌    | ✅     | ❌    | ❌     |
| T9  | NtCreateSection + NtMapViewOfSection| notepad.exe | ✅    | ✅     | ❌    | ❌     |
| T10 | Module Stomping (amsi.dll)          | notepad.exe | ✅    | ✅     | ✅    | ❌     |
| T11 | Process Doppelganging               | -           | ❌    | ❌     | ❌    | ❌     |
| T12 | SetWindowsHookEx                    | system-wide | ❌    | ❌     | ✅    | ❌     |
| T13 | AddressOfEntryPoint                 | notepad.exe | ✅    | ✅     | ❌    | ❌     |
| T14 | PE Injection                        | notepad.exe | ✅    | ✅     | ❌    | ❌     |

---

## Methodology
Each technique was implemented in C++ compiled with MinGW on the Windows 11 VM. The general workflow for each technique was:
1. Write injector code targeting notepad.exe
2. Generate shellcode payload with msfvenom on Kali
3. Start nc listener on Kali
4. Run injector on Win11 VM
5. Capture all Sysmon events in Elastic/Kibana
6. Analyse events, document what fired and what was missing
7. Tune Sysmon config based on findings
8. Document detection gaps and key indicators

Config was iteratively updated throughout the lab as new access mask values and detection patterns were discovered. All GrantedAccess values in the ProcessAccess rule were validated against real observed events rather than theoretical values.

---

## Key Findings

| Finding                                              | Impact                              |
|------------------------------------------------------|-------------------------------------|
| EID 8 alone misses 5 techniques                      | APC, Hollow, Hijack, Hook, Doppel   |
| EID 7 only fires when Windows loader used            | Reflective and PE injection evade   |
| EID 25 only catches main process image replacement   | Module stomping evades EID 25       |
| Direct syscalls do not evade Sysmon                  | Kernel callbacks unaffected         |
| SetWindowsHookEx needs no process handle             | No EID 10 generated                 |
| UNKNOWN in CallTrace                                 | Visible across many techniques       |
| Named module + StartFunction: -                      | stomping indicator T10 T13 fingerprint                 |
| GrantedAccess minimal possible                       | Multiple distinct value possible   |

---

## Sysmon Config Updates Made During Lab

| Update                                    | Reason                                    |
|-------------------------------------------|-------------------------------------------|
| Added 0x102a to GrantedAccess list        | T6 DLL injection actual observed value    |
| Added 0x1428 to GrantedAccess list        | T8 thread hijacking observed value        |
| Added 0x140a to GrantedAccess list        | T9 section injection observed value       |
| Added 0x3fff to GrantedAccess list        | T7 Metasploit injection handle value      |

---

## References

- [Red Team Notes — Process Injection](https://www.ired.team/offensive-security/code-injection-process-injection)
- [Olaf Hartong Sysmon Modular Config](https://github.com/olafhartong/sysmon-modular)
- [Sysmon — Microsoft Sysinternals](https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon)
- [MITRE ATT&CK T1055 — Process Injection](https://attack.mitre.org/techniques/T1055/)
