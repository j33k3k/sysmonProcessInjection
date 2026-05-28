# Comparision of Sysmon and Elastic Defend fields

## Sysmon Config discoveries
- In the config there needs to be a explicit rule included for the include/exclude RuleGroups to trigger, had missed on the include and did not trigger any eid 6

## Eid 1 Process Create
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


## EID 4 SKIPPED

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
