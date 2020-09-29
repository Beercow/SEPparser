# Traffic Log File Format
The traffic log for SEP can be found at the following location:
C:\ProgramData\Symantec\Symantec Endpoint Protection\CurrentVersion\Data\Logs\tralog.log

## Header
| Field                 | Type   | Size | Description                      |
|---------------------- | ------ | :--: | -------------------------------- |
| Log Type              | int    | 4    | Always 00000002                  |
| Max Log Size          | int    | 4    | Maximum log file size in bytes   |
| Unknown               | int    | 4    | ?                                |
| Number of Entries     | int    | 4    | Number of entries in log         |
| Unknown               | int    | 4    | ?                                |
| Running Total Entries | bigint | 8    | Total number of events generated |
| Max Log Days          | int    | 4    | Maximun days to save log entries |


## Log Entries
The log is in TSV format, meaning, each field is separated by a tab character. 

| Field            | Type      | Size | Description                                                                                                        |
| ---------------- | --------- | :--: | ------------------------------------------------------------------------------------------------------------------ |
| Entry Length     | int       | 4    | Length of log entry                                                                                                |
| Date and Time    | bigint    | 8    | The time of the generated event (GMT).                                                                             |
| Protocol         | tinyint   | 1    | The protocol type. (OTHERS = 1; TCP = 2; UDP = 3; ICMP = 4)                                                        |
| Local Host       | bigint    | 8    | The IP address of the local computer (IPv4).                                                                       |
| Remote Host      | bigint    | 8    | The IP address of the remote computer (IPv4).                                                                      |
| Local Port       | int       | 4    | The TCP/UDP port of the local computer (host byte-order). It is only valid on<br>TSE_TRAFFIC_TCP and TSE_TRAFFIC_UDP. For other events, it is always zero. |
| Remote Port      | int       | 4    | The TCP/UDP port of the remote computer (host byte-order). It is only valid on<br>TSE_TRAFFIC_TCP and TSE_TRAFFIC_UDP. For other events, it is always zero. |
| Direction        | tinyint   | 1    | The direction of traffic. (Unknown = 0; inbound = 1; outbound = 2)                                                 |
| End Time         | bigint    | 8    | The end time of the security issue. This field is an optional field because the exact<br>end time of traffic may not be detected; for example, as with UDP traffic. If the end<br>time is not detected, it is set to equal the start time. |
| Begin Time       | bigint    | 8    | The start time of the security issue.                                                                              |
| Occurrences      | int       | 4    | The number of attacks. Sometime, when a hacker launches a mass attack, it may<br>be reduced to one event by the log system, depending on the damper period. |
| Action           | tinyint   | 1    | Specifies if the traffic was blocked. (Yes = 1, no = 0)                                                            |
| Unknown          | ?         | ?    | Will require further investigation as to the purpose of this log entry.                                            |
| Severity         | int       | 4    | Severity as defined in the security rule.<br>Critical = 0 - 3<br>Major = 4 - 7<br>Minor = 8 - 11<br>Info = 12 - 15 |
| Rule ID          | char      | 32   | The ID of the rule that is triggered by the event. It is always 0 if the rule ID is not<br>specified in the security rule. This field is helpful to security rule troubleshooting. If<br>multiple rules match, it logs the rule that has the final decision on PacketProc<br>(pass/block/drop). |
| Remote Host Name | nvarchar  | 128  | The host name of the remote computer. This field may be empty if the name resolution failed.                       |
| Rule             | nvarchar  | 512  | The name of the rule that was triggered by the event. If the rule name is not<br>specified in the security rule, then this field is empty. Having the rule name can<br>be useful for troubleshooting. You may recognize a rule by the rule ID, but rule<br>name can help you recognize it more quickly.
| Application      | nvarchar  | 512  | The full path of application involved. It may be empty if an unknown application<br>is involved or if no application is involved. For example, the ping of death DoS<br>attack does not have AppName because it attacks the operating system itself. |
| Local MAC        | varchar   | 18   | The MAC address of the local computer.                                                                             |
| Remote MAC       | varchar   | 18   | The MAC address of the remote computer.                                                                            |
| Location         | nvarchar  | 512  | The location used when the event occured.                                                                          | 
| User             | nvarchar  | 512  | The logon user name.                                                                                               |
| User Domain      | nvarchar  | 512  | The logon domain name.                                                                                             |
| Unknown          | ?         | ?    | Will require further investigation as to the purpose of this log entry.                                            | 
| Unknown          | ?         | ?    | Will require further investigation as to the purpose of this log entry.                                            | 
| Remote Host IPV6 | varchar   | 32   | The IP address of the remote host (IPv6).                                                                          |
| Local Host IPV6  | varchar   | 32   | The IP address of the local comuter (IPv6).                                                                        |
| Unknown          | ?         | ?    | Will require further investigation as to the purpose of this log entry.                                            |
| Unknown          | ?         | ?    | Will require further investigation as to the purpose of this log entry.                                            |
| MD5              | char      | 32   | The MD5 hash of the executable that triggered the firewall rule.                                                   |
| SHA-256          | char      | 64   | The SHA256 hash of the executable that triggered the firewall rule.                                                |
| Unknown          | ?         | ?    | Will require further investigation as to the purpose of this log entry.                                            |
| Unknown          | ?         | ?    | Will require further investigation as to the purpose of this log entry.                                            |
| Unknown          | ?         | ?    | Will require further investigation as to the purpose of this log entry.                                            | 