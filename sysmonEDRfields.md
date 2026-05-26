# Comparision of Sysmon and Elastic Defend fields

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
