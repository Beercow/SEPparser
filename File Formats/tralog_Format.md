# Traffic Log File Format
The traffic log for SEP can be found at the following location:
* Windows  
C:\ProgramData\Symantec\Symantec Endpoint Protection\CurrentVersion\Data\Logs\tralog.log
* Linux  
 /var/symantec/Logs/tralog.log

## Header
| Field                 | Type   | Size | Description                      |
|---------------------- | ------ | :--: | -------------------------------- |
| Log Type              | hex    | 8    | Always 00000002                  |
| Max Log Size          | hex    | 8    | Maximum log file size in bytes   |
| Unknown               | hex    | 8    | ?                                |
| Number of Entries     | hex    | 8    | Number of entries in log         |
| Unknown               | hex    | 8    | ?                                |
| Running Total Entries | hex    | 16   | Total number of events generated |
| Max Log Days          | hex    | 8    | Maximun days to save log entries |


## Log Entries
The log is in TSV format, meaning, each field is separated by a tab character. 

| Field            | Type      | Size | Description                                                                                                        |
| ---------------- | --------- | :--: | ------------------------------------------------------------------------------------------------------------------ |
| Entry Length     | hex       | 8    | Length of log entry                                                                                                |
| Date and Time    | Windows: 64 bit Hex Value - Big Endian | 16   | The time of the generated event (GMT).                                                                             |
| Event ID         | hex       | 8    | An event ID from the sending agent:<br>301 = TCP initiated<br>302 = UDP datagram<br>303 = Ping request<br>304 = TCP completed<br>305 = Traffic (other)<br>306 = ICMPv4 packet<br>307 = Ethernet packet<br>308 = IP packet<br>309 = ICMPv6 packet **&#42;** |
| Local Host       | hex       | 8    | The IP address of the local computer (IPv4).                                                                       |
| Remote Host      | hex       | 8    | The IP address of the remote computer (IPv4).                                                                      |
| Local Port       | hex       | 8    | The TCP/UDP port of the local computer (host byte-order). It is only valid on<br>TSE_TRAFFIC_TCP and TSE_TRAFFIC_UDP. For other events, it is always zero. |
| Remote Port      | hex       | 8    | The TCP/UDP port of the remote computer (host byte-order). It is only valid on<br>TSE_TRAFFIC_TCP and TSE_TRAFFIC_UDP. For other events, it is always zero. |
| Direction        | hex       | 8    | The direction of traffic. (Unknown = 0; inbound = 1; outbound = 2)                                                 |
| Begin Time       | Windows: 64 bit Hex Value - Big Endian | 16   | The start time of the security issue.                                                                              |
| End Time         | Windows: 64 bit Hex Value - Big Endian | 16    | The end time of the security issue. This field is an optional field because the exact<br>end time of traffic may not be detected; for example, as with UDP traffic. If the end<br>time is not detected, it is set to equal the start time. |
| Repetition       | hex       | 8    | The number of attacks. Sometime, when a hacker launches a mass attack, it may<br>be reduced to one event by the log system, depending on the damper period. |
| Action           | hex       | 8    | Specifies if the traffic was blocked. (Yes = 1, no = 0)                                                            |
| Unknown          | hex       | 8    | Will require further investigation as to the purpose of this log entry.                                            |
| Severity         | hex       | 8    | Severity as defined in the security rule.<br>Critical = 0 - 3<br>Major = 4 - 7<br>Minor = 8 - 11<br>Info = 12 - 15 |
| Rule ID          | char      | 32   | The ID of the rule that is triggered by the event. It is always 0 if the rule ID is not<br>specified in the security rule. This field is helpful to security rule troubleshooting. If<br>multiple rules match, it logs the rule that has the final decision on PacketProc<br>(pass/block/drop). |
| Remote Host Name | nvarchar  | 128  | The host name of the remote computer. This field may be empty if the name resolution failed.                       |
| Rule             | nvarchar  | 512  | The name of the rule that was triggered by the event. If the rule name is not<br>specified in the security rule, then this field is empty. Having the rule name can<br>be useful for troubleshooting. You may recognize a rule by the rule ID, but rule<br>name can help you recognize it more quickly.
| Application      | nvarchar  | 512  | The full path of application involved. It may be empty if an unknown application<br>is involved or if no application is involved. For example, the ping of death DoS<br>attack does not have AppName because it attacks the operating system itself. |
| Local MAC        | binary    | 32   | The MAC address of the local computer.                                                                             |
| Remote MAC       | binary    | 32   | The MAC address of the remote computer.                                                                            |
| Location         | nvarchar  | 512  | The location used when the event occured.                                                                          | 
| User             | nvarchar  | 512  | The logon user name.                                                                                               |
| User Domain      | nvarchar  | 512  | The logon domain name.                                                                                             |
| Unknown          | hex       | 8    | Will require further investigation as to the purpose of this log entry.                                            | 
| Unknown          | hex       | 8    | Will require further investigation as to the purpose of this log entry.                                            | 
| Remote Host IPV6 | hex       | 32   | The IP address of the remote host (IPv6).                                                                          |
| Local Host IPV6  | hex       | 32   | The IP address of the local comuter (IPv6).                                                                        |
| Unknown          | hex       | 8    | Will require further investigation as to the purpose of this log entry.                                            |
| Unknown          | hex       | 8    | Will require further investigation as to the purpose of this log entry.                                            |
| MD5              | char      | 32   | The MD5 hash of the executable that triggered the firewall rule.                                                   |
| SHA-256          | char      | 64   | The SHA256 hash of the executable that triggered the firewall rule.                                                |
| Unknown          | ?         | ?    | Will require further investigation as to the purpose of this log entry.                                            |
| Unknown          | ?         | ?    | Will require further investigation as to the purpose of this log entry.                                            |
| Unknown          | ?         | ?    | Will require further investigation as to the purpose of this log entry.                                            | 

**&#42; SEP14.2.1**

NTOSKRNL is a special SYSTEM process with PID 4. Due to how Windows locks the file, SEP is unable to get the hash, so it was hard-coded with a static value.  
MD5: 53797320000000000000000000000000  
SHA-256: 5379732000000000000000000000000000000000000000000000000000000000

This value is a hexadecimal representation of text:  
Hex: 53 79 73 20  
Ascii: "Sys "

The reported hash on NTSOKRNL.exe is by design. 