# Packet Log File Format
The packet log for SEP can be found at the following location:
C:\ProgramData\Symantec\Symantec Endpoint Protection\CurrentVersion\Data\Logs\rawlog.log

## Header
| Field                 | Type   | Size | Description                      |
|---------------------- | ------ | :--: | -------------------------------- |
| Log Type              | hex    | 8    | Always 00000003                  |
| Max Log Size          | hex    | 8    | Maximum log file size in bytes   |
| Unknown               | hex    | 8    | ?                                |
| Number of Entries     | hex    | 8    | Number of entries in log         |
| Unknown               | hex    | 8    | ?                                |
| Running Total Entries | hex    | 16   | Total number of events generated |
| Max Log Days          | hex    | 8    | Maximun days to save log entries |


## Log Entries
The log is in TSV format, meaning, each field is separated by a tab character. 

| Field            | Type                                   | Size | Description                                                                                                                                                 |
| ---------------- | -------------------------------------- | :--: | ----------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Entry Length     | hex                                    | 8    | Length of log entry                                                                                                                                         |
| Date and Time    | Windows: 64 bit Hex Value - Big Endian | 16   | The time of the generated event (GMT).                                                                                                                      |
| Event ID         | hex                                    | 8    | An event ID from the sending agent:<br>401 = Raw Ethernet                                                                                                   |
| Local Host       | hex                                    | 8    | The IP address of the local computer (IPv4).                                                                                                                |
| Remote Host      | hex                                    | 8    | The IP address of the remote computer (IPv4).                                                                                                               |
| Local Port       | hex                                    | 8    | The TCP/UDP port of the local computer (host byte-order). It is only valid on<br>TSE_TRAFFIC_TCP and TSE_TRAFFIC_UDP. For other events, it is always zero.  |
| Remote Port      | hex                                    | 8    | The TCP/UDP port of the remote computer (host byte-order). It is only valid on<br>TSE_TRAFFIC_TCP and TSE_TRAFFIC_UDP. For other events, it is always zero. |
| Packet Length    | hex                                    | 8    | Lenght of packet data                                                                                                                                       |
| Direction        | hex                                    | 8    | The direction of traffic (unknown = 0; inbound = 1; outbound = 2).                                                                                          |
| Action           | hex                                    | 8    | Specifies if the traffic was blocked (yes = 1, no = 0).                                                                                                     |
| Unknown          | hex                                    | 8    | Will require further investigation as to the purpose of this log entry.                                                                                     |
| Remote Host Name | nvarchar                               | 128  | The host name of the remote computer. This field may be empty if the name resolution failed.                                                                |
| Application      | nvarchar                               | 512  | The full path name of the application involved. It may be empty if an unknown<br>application is involved or if no application is involved. For example, the ping of<br>death DoS attack does not have an AppName because it attacks the operating<br>system. |
| Packet           | varbinary                              | 2000 |                                                                                                                                                             |
| Rule             | nvarchar                               | 512  | The name of the rule that was triggered by the event. If the rule name is not<br>specified in the security rule, then this field is empty. Having the rule name can<br>be useful for troubleshooting. You may recognize a rule by the rule ID, but rule<br>name can help you recognize it more quickly. 
| Unknown          | hex                                    | 8    | Will require further investigation as to the purpose of this log entry.                                                                                     |
| Unknown          | hex                                    | 8    | Will require further investigation as to the purpose of this log entry.                                                                                     |
| Remote Host IPV6 | hex                                    | 32   | The IP address of the remote host (IPv6).                                                                                                                   |
| Local Host IPV6  | hex                                    | 32   | The IP address of the local computer (IPv6).                                                                                                                |
| Rule ID          | cahr                                   | 32   | The ID of the rule that is triggered by the event. It is always 0 if the rule ID is not<br>specified in the security rule. This field is helpful to security rule troubleshooting.<br>If multiple rules match, it logs the rule that has the final decision on PacketProc<br>(pass/block/drop). |