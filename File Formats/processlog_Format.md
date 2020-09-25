# Control Log File Format
The control log for SEP can be found at the following location:
C:\ProgramData\Symantec\Symantec Endpoint Protection\CurrentVersion\Data\Logs\processlog.log

## Header
| Field                 | Type   | Size | Description                       |
|---------------------- | ------ | :--: | --------------------------------- |
| Log Type              | int    | 4    | Always 00000004                   |
| Max Log Size          | int    | 4    | Maximum log file size in bytes    |
| Unknown               | int    | 4    | ?                                 |
| Number of Entries     | int    | 4    | Number of entries in log          |
| Unknown               | int    | 4    | ?                                 |
| Running Total Entries | bigint | 8    | Totoal number of events generated |
| Max Log Days          | int    | 4    | Maximun days to save log entries  |


## Log Entries
The log is in TSV format, meaning, each field is separated by a tab character. 

| Field              | Type      | Size | Description                                                                                      |
| ------------------ | --------- | :--: | ------------------------------------------------------------------------------------------------ |
| Entry Length       | int       | 4    | Length of log entry                                                                              |
| Date and Time      | bigint    | 8    | The time of the generated event (GMT).                                                           |
| Unknown            |           |      | ?                                                                                                |
| Severity           |           |      | The seriousness of the event<br>0 is most serious.                                               |
| Action             |           |      | The action that was taken:<br>0 = allow<br>1 = block<br>2 = ask<br>3 = continue<br>4 = terminate |
| Test Mode          |           |      | Was this rule run in test mode?<br>0 = No, Else = Yes                                            |
| Description        | nvarchar  | 8000 | The behavior that was blocked.<br><br>Because of a character limit, actual values may be longer than the values that<br>are displayed in Symantec Endpoint Protection Manager. You can verify the full<br>text on the client that reports this data. |
| API                | nvarchar  | 512  | The API that was blocked.                                                                        |
| Unknown            |           |      | ?                                                                                                |
| Begin Time         |           |      | The start time of the security issue.                                                            |
| End Time           |           |      | The end time of the security issue. This field is an optional field because the<br>exact end time of traffic may not be detected; for example, as with UDP traffic.<br>If the end time is not detected, it is set to equal the start time. |
| Rule Name          | nvarchar  | 512  | The name of the rule that was triggered by the event. If the rule name is not<br>specified in the security rule, then this field is empty. Having the rule name can<br>be useful for troubleshooting. |
| Caller Process ID  |           |      | The ID of the process that triggers the logging.                                                 |
| Caller Process     | nvarchar  | 512  | The full path name of the application involved. It may be empty if the<br>application is unknown, or if OS itself is involved, or if no application is involved.<br>Also, it may be empty if profile says, "don't log application name in raw traffic<br>log". |
| Unknown            |           |      | ?                                                                                                |
| Unknown            |           |      | ?                                                                                                |
| Target             |           |      | Name of file                                                                                     |
| Location           | nvarchar  | 512  | The location used when the event occured.                                                        |
| User               | nvarchar  | 512  | The logon user name.                                                                             |
| User Domain        | nvarchar  | 512  | The logon (Windows) domain name.                                                                 |
| IPV4 Address       |           |      | The IP address of the computer associated with the application control violation.                |
| Device Instance ID |           |      | The GUID of an external device (floppy disk, DVD, USB device, etc.).                             |
| File Size          |           |      | The size of the file associated with the application control violation, in bytes.                |
| Unknown            |           |      | ?                                                                                                |
| IPV6 Address       |           |      | The IP address of the computer associated with the application control violation. (IPV6)         |