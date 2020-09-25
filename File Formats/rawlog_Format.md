# Packet Log File Format
The packet log for SEP can be found at the following location:
C:\ProgramData\Symantec\Symantec Endpoint Protection\CurrentVersion\Data\Logs\rawlog.log

## Header
| Field                 | Type   | Size | Description                       |
|---------------------- | ------ | :--: | --------------------------------- |
| Log Type              | int    | 4    | Always 00000003                   |
| Max Log Size          | int    | 4    | Maximum log file size in bytes    |
| Unknown               | int    | 4    | ?                                 |
| Number of Entries     | int    | 4    | Number of entries in log          |
| Unknown               | int    | 4    | ?                                 |
| Running Total Entries | bigint | 8    | Totoal number of events generated |
| Max Log Days          | int    | 4    | Maximun days to save log entries  |


## Log Entries
The log is in TSV format, meaning, each field is separated by a tab character. 

| Field            | Type      | Size | Description                                                                                  |
| ---------------- | --------- | :--: | -------------------------------------------------------------------------------------------- |
| Entry Length     | int       | 4    | Length of log entry                                                                          |
| Date and Time    | bigint    | 8    | The time of the generated event (GMT).                                                       |
| Event ID         |           |      | An event ID from the sending agent:<br>401 = Raw Ethernet                                    |
| Local Host       |           |      | The IP address of the local computer (IPv4).                                                 |
| Remote Host      |           |      | The IP address of the remote computer (IPv4).                                                |
| Local Port       |           |      | The TCP/UDP port of the local computer (host byte-order). It is only valid on<br>TSE_TRAFFIC_TCP and TSE_TRAFFIC_UDP. For other events, it is always zero. |
| Remote Port      |           |      | The TCP/UDP port of the remote computer (host byte-order). It is only valid on<br>TSE_TRAFFIC_TCP and TSE_TRAFFIC_UDP. For other events, it is always zero. |
| Packet Length    |           |      | Lenght of packet data                                                                        |
| Direction        |           |      | The direction of traffic (unknown = 0; inbound = 1; outbound = 2).                           |
| Action           |           |      | Specifies if the traffic was blocked (yes = 1, no = 0).                                      |
| Unknown          |           |      | ?                                                                                            |
| Remote Host Name | nvarchar  | 128  | The host name of the remote computer. This field may be empty if the name resolution failed. |
| Application      | nvarchar  | 512  | The full path name of the application involved. It may be empty if an unknown<br>application is involved or if no application is involved. For example, the ping of<br>death DoS attack does not have an AppName because it attacks the operating<br>system. |
| Packet           |           |      |                                                                                              |
| Rule             | nvarchar  | 512  | The name of the rule that was triggered by the event. If the rule name is not<br>specified in the security rule, then this field is empty. Having the rule name can<br>be useful for troubleshooting. You may recognize a rule by the rule ID, but rule<br>name can help you recognize it more quickly. 
| Unknown          |           |      | ?                                                                                            |
| Unknown          |           |      | ?                                                                                            |
| Remote Host IPV6 |           |      | The IP address of the remote host (IPv6).                                                    |
| Local Host IPV6  |           |      | The IP address of the local computer (IPv6).                                                 |
| Rule ID          | cahr      | 32   | The ID of the rule that is triggered by the event. It is always 0 if the rule ID is not<br>specified in the security rule. This field is helpful to security rule troubleshooting.<br>If multiple rules match, it logs the rule that has the final decision on PacketProc<br>(pass/block/drop). |