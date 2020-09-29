# Antivirus Management Log File Format
The antivirus managment log for SEP can be found at the following location:  
C:\ProgramData\Symantec\Symantec Endpoint Protection\CurrentVersion\Data\Logs\AVMan.log

## Header
| Field                 | Type   | Size | Description                      |
|---------------------- | ------ | :--: | -------------------------------- |
| Max Log Size          | int    | 4    | Maximum log file size in bytes   |
| Unknown               | int    | 4    | ?                                |
| Number of Entries     | int    | 4    | Number of entries in log         |
| Unknown               | int    | 4    | ?                                |
| Unknown               | ?      | ?    | ?                                |
| Max Log Days          | int    | 4    | Maximun days to save log entries |


## Log Entries
The log is in TSV format, meaning, each field is separated by a tab character. 

| Field               | Type      | Size | Description                                                             |
| ------------------- | --------- | :--: | ----------------------------------------------------------------------- |
| Entry Length        | int       | 4    | Length of log entry                                                     |
| Date and Time 1     | bigint    | 8    | Will require further investigation as to the purpose of this log entry. |
| Date and Time 2     | bigint    | 8    | Will require further investigation as to the purpose of this log entry. |
| Date and Time 3     | bigint    | 8    | Will require further investigation as to the purpose of this log entry. |
| Unknown             | ?         | ?    | Will require further investigation as to the purpose of this log entry. |
| Data                | varbinary | 2000 | Additional data in binary format.                                       |