# Antivirus Management Log File Format
The antivirus managment log for SEP can be found at the following location:  
C:\ProgramData\Symantec\Symantec Endpoint Protection\CurrentVersion\Data\Logs\AVMan.log

## Header
| Field                 | Type   | Size | Description                      |
|---------------------- | ------ | :--: | -------------------------------- |
| Max Log Size          | hex    | 8    | Maximum log file size in bytes   |
| Unknown               | hex    | 8    | ?                                |
| Number of Entries     | hex    | 8    | Number of entries in log         |
| Unknown               | hex    | 8    | ?                                |
| Unknown               | hex    | 8    | ?                                |
| Max Log Days          | hex    | 8    | Maximun days to save log entries |


## Log Entries
The log is in TSV format, meaning, each field is separated by a tab character. 

| Field               | Type                                   | Size | Description                                                             |
| ------------------- | -------------------------------------- | :--: | ----------------------------------------------------------------------- |
| Entry Length        | hex                                    | 8    | Length of log entry                                                     |
| Date and Time 1     | Windows: 64 bit Hex Value - Big Endian | 16   | Will require further investigation as to the purpose of this log entry. |
| Date and Time 2     | Windows: 64 bit Hex Value - Big Endian | 16   | Will require further investigation as to the purpose of this log entry. |
| Date and Time 3     | Windows: 64 bit Hex Value - Big Endian | 16   | Will require further investigation as to the purpose of this log entry. |
| Unknown             | hex                                    | 8    | Will require further investigation as to the purpose of this log entry. |
| Data                | varbinary                              | 2000 | Additional data in binary format.                                       |