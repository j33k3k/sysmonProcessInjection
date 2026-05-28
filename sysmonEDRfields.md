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
