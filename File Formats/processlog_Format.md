# Control Log File Format
The control log for SEP can be found at the following location:
* Windows  
C:\ProgramData\Symantec\Symantec Endpoint Protection\CurrentVersion\Data\Logs\processlog.log
* Linux  
 /var/symantec/Logs/seclog.log

## Header
| Field                 | Type   | Size | Description                      |
|---------------------- | ------ | :--: | -------------------------------- |
| Log Type              | hex    | 8    | Always 00000004                  |
| Max Log Size          | hex    | 8    | Maximum log file size in bytes   |
| Unknown               | hex    | 8    | ?                                |
| Number of Entries     | hex    | 8    | Number of entries in log         |
| Unknown               | hex    | 8    | ?                                |
| Running Total Entries | hex    | 16   | Total number of events generated |
| Max Log Days          | hex    | 8    | Maximun days to save log entries |


## Log Entries
The log is in TSV format, meaning, each field is separated by a tab character. 

| Field                     | Type                                   | Size | Description                                                                                      |
| ------------------------- | -------------------------------------- | :--: | ------------------------------------------------------------------------------------------------ |
| Entry Length              | hex                                    | 3    | Length of log entry                                                                              |
| Date and Time             | Windows: 64 bit Hex Value - Big Endian | 16   | The time of the generated event (GMT).                                                           |
| Event ID                  | hex                                    | 3    | An event ID from the sending agent:<br>501 = Application Control Driver<br>502 = Application Control Rules<br>999 = Tamper Protection |
| Severity                  | int                                    | 1    | The seriousness of the event<br>0 is most serious.                                               |
| Action                    | int                                    | 1    | The action that was taken:<br>0 = allow<br>1 = block<br>2 = ask<br>3 = continue<br>4 = terminate |
| Test Mode                 | int                                    | 1    | Was this rule run in test mode?<br>0 = No, Else = Yes                                            |
| Description               | nvarchar                               | 8000 | The behavior that was blocked.<br><br>Because of a character limit, actual values may be longer than the values that<br>are displayed in Symantec Endpoint Protection Manager. You can verify the full<br>text on the client that reports this data. |
| API                       | nvarchar                               | 512  | The API that was blocked.                                                                        |
| Unknown                   | hex                                    | 16   | Will require further investigation as to the purpose of this log entry.                          |
| Begin Time                | Windows: 64 bit Hex Value - Big Endian | 16   | The start time of the security issue.                                                            |
| End Time                  | Windows: 64 bit Hex Value - Big Endian | 16   | The end time of the security issue. This field is an optional field because the<br>exact end time of traffic may not be detected; for example, as with UDP traffic.<br>If the end time is not detected, it is set to equal the start time. |
| Rule Name                 | nvarchar                               | 512  | The name of the rule that was triggered by the event. If the rule name is not<br>specified in the security rule, then this field is empty. Having the rule name can<br>be useful for troubleshooting. |
| Caller Process ID         | hex                                    | 4    | The ID of the process that triggers the logging.                                                 |
| Caller Process            | nvarchar                               | 512  | The full path name of the application involved. It may be empty if the<br>application is unknown, or if OS itself is involved, or if no application is involved.<br>Also, it may be empty if profile says, "don't log application name in raw traffic<br>log". |
| Caller Return Address     | hex                                    | 4    | he return address of the caller. This field allows the detection of the calling module that makes the API call. |
| Caller Return Module Name | nvarchar                               | 512  | The module name of the caller. See CallerReturnAddress for more information.                     |
| Target                    | nvarchar                               | ?    | Name of file                                                                                     |
| Location                  | nvarchar                               | 512  | The location used when the event occured.                                                        |
| User                      | nvarchar                               | 512  | The logon user name.                                                                             |
| User Domain               | nvarchar                               | 512  | The logon (Windows) domain name.                                                                 |
| Unknown                   | int                                    | 1    | Will require further investigation as to the purpose of this log entry.                          |
| Unknown                   | int                                    | 1    | Will require further investigation as to the purpose of this log entry.                          |
| IPV4 Address              | hex                                    | 8    | The IP address of the computer associated with the application control violation.                |
| Device Instance ID        | varchar                                | 256  | The GUID of an external device (floppy disk, DVD, USB device, etc.).                             |
| File Size                 | hex                                    | 2    | The size of the file associated with the application control violation, in bytes.                |
| Unknown                   | hex                                    | 8    | Will require further investigation as to the purpose of this log entry.                          |
| IPV6 Address              | hex                                    | 32   | The IP address of the computer associated with the application control violation. (IPV6)         |