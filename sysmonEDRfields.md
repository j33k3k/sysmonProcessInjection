# Comparision of Sysmon and Elastic Defend fields

## Eid 1 Process Create
Sysmon EID 1 fires on every `CreateProcess`. Elastic Defend generates `process` events with `event.action: start` via its kernel-mode driver (`ElasticEndpoint.sys`), capturing similar telemetry through ETW + kernel callbacks.

| Sysmon field | Elastic Defend field | Comment |
|---|---|---|
| `RuleName` | `-` | Missing custom rule name |
| `UtcTime` | `@timestamp` | |
| `ProcessGuid` | `process.entity_id` | |
| `ProcessId` | `process.pid` | |
| `Image` | `process.executable` | |
| `FileVersion` | `-` | Not needed |
| `Description` | `-` | Not available |
| `Product` | `-` | Not needed but `process.name` |
| `Company` | `-` | Could use `process.code_signature.subject_name` as well |
| `OriginalFileName` | `process.pe.original_file_name` | |
| `CommandLine` | `process.command_line` | |
| `CurrentDirectory` | `process.working_directory` | |
| `User` | `user.name` | But also `user.domain` and `user.id` |
| `LogonGuid` | `-` | Not available but get `process.Ext.session_info*` with logon type etc |
| `LogonId` | `process.Ext.authentication_id` | |
| `TerminalSessionId` | `process.Ext.session_info.id` | |
| `IntegrityLevel` | `process.Ext.token.integrity_level_name` | Additional `process.Ext.token*` fields like privileges, groups, elevation type |
| `Hashes` | `process.hash.sha256` | `process.pe.imphash`as well but no other by default |
| `ParentProcessGuid` | `process.parent.entity_id` | |
| `ParentProcessId` | `process.parent.pid` | `process.Ext.ancestry` also for full chain |
| `ParentImage` | `process.parent.executable` | |
| `ParentCommandLine` | `process.parent.command_line` | |
| `ParentUser` | `-` | Not available | |  
 
 *Comment:* EDR has more fields focused on code signing, token integrity, and session info.


## Eid 2 A process changed a file creation time 
Sysmon EID 2 fires when a process modifies the creation timestamp of a file (timestomping). Elastic Defend captures this via file events with event.action: "change".
