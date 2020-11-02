# Security Log File Format
The security log for SEP can be found at the following location:
C:\ProgramData\Symantec\Symantec Endpoint Protection\CurrentVersion\Data\Logs\seclog.log

## Header
| Field                 | Type   | Size | Description                      |
|---------------------- | ------ | :--: | -------------------------------- |
| Log Type              | hex    | 8    | Always 00000001                  |
| Max Log Size          | hex    | 8    | Maximum log file size in bytes   |
| Unknown               | hex    | 8    | ?                                |
| Number of Entries     | hex    | 8    | Number of entries in log         |
| Unknown               | hex    | 8    | ?                                |
| Running Total Entries | hex    | 16   | Total number of events generated |
| Max Log Days          | hex    | 8    | Maximun days to save log entries |


## Log Entries
The log is in TSV format, meaning, each field is separated by a tab character. 

| Field                       | Type                                   | Size | Description                                                                                                            |
| --------------------------- | -------------------------------------- | :--: | ---------------------------------------------------------------------------------------------------------------------- |
| Entry Length                | hex                                    | 8    | Length of log entry                                                                                                    |
| Date and Time               | Windows: 64 bit Hex Value - Big Endian | 16   | The time of the generated event (GMT).                                                                                 |
| Event ID                    | hex                                    | 8    | Compliance events:<br>209 = Host Integrity failed.<br>210 = Host Integrity passed.<br>221 = Host Integrity failed, but reported as passed.<br>237 = Host Integrity custom log entry.<br><br>Firewall and IPS events:<br>201 = Invalid traffic by rule. **&#42;**<br>202 = Port scan. **&#42;**<br>203 = Denial of service. **&#42;**<br>204 = Trojan. **&#42;**<br>205 = Executable file was changed. **&#42;**<br>206 = Intrusion Prevention System Intrusion was detected. **&#42;**<br>207 = Active Response.<br>208 = MAC spoofing. **&#42;**<br>211 = Active Response was disengaged.<br>216 = Executable file change was detected.<br>217 = Executable file change was accepted.<br>218 = Executable file change was denied.<br>219 = Active Response was cancelled. **&#42;**<br>220 = Application hijacking.<br>249 = Browser Protection event.<br><br>Application and Device control:<br>238 = Device control disabled the device.<br>239 = Buffer Overflow event.<br>240 = Software protection has thrown an exception.<br>241 = Not used. **&#42;**<br>242 = Device control enabled the device. **&#42;**<br><br>Memory Exploit Mitigation events: **&#42;**<br>250 = Memory Exploit Mitigation blocked an event. **&#42;**<br>251 = Memory Exploit Mitigation allowed an event. **&#42;** |
| Severity                    | hex                                    | 8    | The severity as defined in the security rule.<br>Critical = 0 - 3<br>Major = 4 - 7<br>Minor = 8 - 11<br>Info = 12 - 15 | 
| Local Host                  | hex                                    | 8    | The IP address of the local computer (IPv4).                                                                           |
| Remote Host                 | hex                                    | 8    | The IP address of the remote computer (IPv4).                                                                          |
| Protocol                    | hex                                    | 8    | The protocol type. (OTHERS = 1; TCP = 2; UDP = 3; ICMP = 4)                                                            |
| Unknown                     | hex                                    | 8    | Will require further investigation as to the purpose of this log entry.                                                |
| Direction                   | hex                                    | 8    | The direction of traffic. (Unknown = 0; inbound = 1; outbound = 2)                                                     |
| End Time                    | Windows: 64 bit Hex Value - Big Endian | 16   | The end time of the security issue. This field is an optional field<br>because the exact end time of traffic may not be detected; for example,<br>as with UDP traffic. If the end time is not detected, it is set to equal the<br>start time. |
| Begin Time                  | Windows: 64 bit Hex Value - Big Endian | 16   | The start time of the security issue.                                                                                  |
| Occurences                  | hex                                    | 8    | The number of attacks. Sometime, when a hacker launches a mass<br>attack, it may be reduced to one event by the log system, depending<br>on the damper period. | 
| Log Data Size               | hex                                    | 8    |                                                                                                                        |
| Description                 | nvarchar                               | 4000 | Description of the event. Usually, the first line of the description is<br>treated as the summary.                     |
| Unknown                     | ?                                      | ?    | Will require further investigation as to the purpose of this log entry.                                                |
| Application                 | nvarchar                               | 512  | The full path of the application involved. This field may be empty if<br>an unknown application is involved, or no application is involved. For<br>example, the ping of death DoS attack does not have an application<br>name because it attacks the OS itself. |
| Log Data                    | varbinary                              | 3000 | Additional data in binary format. This field is optional.                                                              |
| Local MAC                   | binary                                 | 32   | The MAC address of the local computer.                                                                                 |
| Remote MAC                  | binary                                 | 32   | The MAC address of the remote computer.                                                                                |
| Location                    | nvarchar                               | 512  | The location used when the event occured.                                                                              | 
| User                        | nvarchar                               | 512  | The logon user name.                                                                                                   |
| User Domain                 | nvarchar                               | 512  | The logon domain name.                                                                                                 |
| Signature ID                | hex                                    | 8    | The signature ID.                                                                                                      |
| Signature Sub ID            | hex                                    | 8    | The signature sub ID.                                                                                                  |
| Unknown                     | hex                                    | 8    | Will require further investigation as to the purpose of this log entry.                                                |
| Unknown                     | hex                                    | 8    | Will require further investigation as to the purpose of this log entry.                                                |
| Remote Port                 | hex                                    | 8    | The remote port.                                                                                                       |
| Locacl Port                 | hex                                    | 8    | The local port.                                                                                                        |
| Local Host IPV6             | hex                                    | 32   | The IP address of the local computer (IPv6).                                                                           |
| Remote Host IPV6            | hex                                    | 32   | The IP address of the remote computer (IPv6).                                                                          | 
| Signature Name              | nvarchar                               | 520  | The signature name.                                                                                                    |  
| X Intrusion Payload         | nvarchar                               | 4200 | The URL that hosted the payload.                                                                                       |
| Intrusion URL               | nvarchar                               | 4200 | The URL from the detection                                                                                             |
| Unknown                     | ?                                      | ?    | Will require further investigation as to the purpose of this log entry.                                                |
| Symantec Version Number     | nvarchar                               | 128  | The agent version number on the client.                                                                                | 
| Profile Serial Number       | varchar                                | 64   | The policy serial number.                                                                                              |
| Unknown                     | hex                                    | 8    | Will require further investigation as to the purpose of this log entry.                                                | 
| MD5 Hash                    | char                                   | 32   | The MD5 hash value.                                                                                                    |
| SHA-256 Hash                | char                                   | 64   | The SHA-256 hash value.                                                                                                |
| URL_HID_LEVEL **&dagger;**  | hex                                    | 8    | Added for future release. Not used now.                                                                                |
| URL_RISK_SCORE **&dagger;** | hex                                    | 8    | Added for future release. Not used now.                                                                                |
| URL_CATEGORIES **&dagger;** | char                                   | 64   | Added for future release. Not used now.                                                                                |

**&#42; SEP14.2.1**  
**&dagger; SEP14.3.0.1**