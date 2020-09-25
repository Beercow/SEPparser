# Antivirus Management Log File Format
The antivirus managment log for SEP can be found at the following location:  
C:\ProgramData\Symantec\Symantec Endpoint Protection\CurrentVersion\Data\Logs\AVMan.log

## Header
| Field                 | Type   | Size | Description                       |
|---------------------- | ------ | :--: | --------------------------------- |
| Max Log Size          | int    | 4    | Maximum log file size in bytes    |
| Unknown               | int    | 4    | ?                                 |
| Number of Entries     | int    | 4    | Number of entries in log          |
| Unknown               | int    | 4    | ?                                 |
| Unknown               |        |      | ?                                 |
| Max Log Days          | int    | 4    | Maximun days to save log entries  |


## Log Entries
The log is in TSV format, meaning, each field is separated by a tab character. 

| Field               | Type      | Size | Description         |
| ------------------- | --------- | :--: | ------------------- |
| Entry Length        |           | 4    | Length of log entry |
| Date and Time 1     |           | 8    | ?                   |
| Date and Time 2     |           | 4    | ?                   |
| Date and Time 3     |           | 4    | ?                   |
| Unknown             |           | 4    | ?                   |
| Data                |           | 4    | ?                   |