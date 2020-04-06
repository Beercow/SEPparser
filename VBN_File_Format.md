# VBN file format V2 (Windows - SEP 12 +)

<table width="1500">
<tr><th>VBN Metadata</th></tr>
<tr align="center"><td>

| Offset | Length | Field                | Description                                                                              |
| ------ | ------ | -------------------- | ---------------------------------------------------------------------------------------- |
| 0      | 4      | Size                 | Size of the VBN Metadata section                                                         |
| 4      | 384    | Description          | FQP of Quarantine File                                                                   |
| 388    | 2048   | Log Line             | Information on event.                                                                    |
| 2436   | 4      | Data Type            | Value which can describe the subsequent data. (0x1 = No dates, 0x2 = Dates)              |
| 2440   | 4      | Record ID            | VBin ID/VBN Name                                                                         |
| 2444   | 8      | Date Modified        | Indicates a time of last modification of content. (Windows Filetime)                     |
| 2452   | 8      | Date Created         | Indicates a time of creation of object on the file system. (Windows Filetime)            |
| 2460   | 8      | Date Accessed        | Indicates a time of last access of an object. (Windows Filetime)                         |
| 2468   | 4      | Data Type            | Value which can describe the subsequent data. (0x0 = No storage info, 0x2 = Storage info |
| 2472   | 484    | Unknown              | ?                                                                                        |
| 2956   | 48     | Storage Name         | Appears to always be FileSystem                                                          |
| 3004   | 4      | Storage Instance ID  | Appears to always be 130                                                                 |
| 3008   | 384    | Storage Key          | ?                                                                                        |
| 3392   | 4      | Data Type            | Value which can describe the subsequent data.                                            |
| 3396   | 4      | Unknown              | ?                                                                                        |
| 3400   | 8      | Unknown              | ?                                                                                        |
| 3408   | 4      | Data Type            | Value which can describe the subsequent data.                                            |
| 3412   | 4      | Quarantine File Size | Size of Quarantined File (bytes)                                                         |
| 3416   | 8      | Date Created         | Indicates a time of creation of object on the file system. (Unix: 32 bit Hex)            |
| 3424   | 8      | Date Accessed        | Indicates a time of last access of an object. (Unix: 32 bit Hex)                         |
| 3432   | 8      | Date Modified        | Indicates a time of last modification of content. (Unix: 32 bit Hex)                     |
| 3440   | 8      | VBin Time            | Time file was quarantined. (Unix: 32 bit Hex)                                            |
| 3448   | 4      | Unknown              | ?                                                                                        |
| 3452   | 16     | Unique ID            | Unique GUID                                                                              |
| 3468   | 260    | Unknown              | ?                                                                                        |
| 3728   | 4      | Unknown              | ?                                                                                        |
| 3732   | 4      | Record Type          | 0x0 = Hybrid, 0x1 = Meta, 0x2 = Quarantine                                               |
| 3736   | 4      | Folder Name          | Name of subfolder where VBN is stored                                                    |
| 3740   | 4      | Unknown              | ?                                                                                        |
| 3744   | 4      | Unknown              | ?                                                                                        |
| 3748   | 4      | Unknown              | ?                                                                                        |
| 3752   | 4      | Unknown              | ?                                                                                        |
| 3756   | 4      | Unknown              | ?                                                                                        |
| 3760   | 4      | Unknown              | ?                                                                                        |
| 3764   | 4      | Unknown              | ?                                                                                        |
| 3768   | 4      | Unknown              | ?                                                                                        |
| 3772   | 768    | Wide Description     | FQP of Quarantine File (Unicode)                                                         |
| 4540   | 212    | Unknown              | ?                                                                                        |

The following sections are XORed with 0x5A  
The Record Type determines what comes next
</td></tr></table>
<table width="1500">
<tr><th>Record Type 0</th><th>Record Type 1</th><th>Record Type 2</th></tr>
<tr valign="top"><td>

### QData Location (Optional)

| Offset | Length | Field                    | Description                             |
| ------ | :----: | ------------------------ | --------------------------------------- |
| 0      | 8      | Header                   | QData location header, 0x6aaaa20ce      |
| 8      | 8      | File Offset              | Offset to start of quarantine data      |
| 16     | 8      | Data Size                | Size of quarantine data                 |
| 24     | 4      | EOF                      | Size from end of quarantine data to EOF |
| 28     | Varies | Unknown                  | ?                                       |

### Quarantine Data

| Offset | Length | Field | Description     |
| ------ | :----: | ----- | --------------- |
| 0      | Varies | Data  | Quarantine data |

### QData Info (Optional)

| Offset | Length | Field           | Description                                      |
| ------ | :----: | --------------- | ------------------------------------------------ |
| 0      | 8      | Header          | QData info header                                |
| 8      | 8      | QData Info Size | Size of QData info                               |
| 16     | Varies | QData           | Additional information about the quarantine data |

</td><td>

### Quarantine File Metadata

The quarantine file metadata appears to be in ASN.1 format. It is comprised of a series of tags.

| Code | Value Length | Extra Data                                                                        |
| ---- | :----------: | --------------------------------------------------------------------------------- |
| 0x01 | 1            | None                                                                              |
| 0x0A | 1            | None                                                                              |
| 0x03 | 4            | None                                                                              |
| 0x06 | 4            | None                                                                              |
| 0x04 | 8            | None                                                                              |
| 0x07 | 4            | NUL-terminated ASCII String (of length controlled by dword following 0x07 code)   |
| 0x08 | 4            | NUL-terminated Unicode String (of length controlled by dword following 0x08 code) |
| 0x09 | 4            | Container (of length controlled by dword following 0x09 code)                     |

</td><td>

### Quarantine File Metadata Header

| Offset | Length | Field                    | Description                                   |
| ------ | :----: | ------------------------ | --------------------------------------------- |
| 0      | 8      | QFM Header               | Header is always 0000000000000000             |
| 8      | 8      | QFM Header Size          | Size, in bytes, of the QFM header             |
| 16     | 8      | QFM Size                 | Size, in bytes, of the QFM                    |
| 24     | 8      | QFM Size + Header Size   | Size, in bytes, of the QFM and header         |
| 32     | 8      | End of QFM to End of VBN | Size, in bytes, from end of QFM to end of VBN |

### Quarantine File Metadata

The quarantine file metadata appears to be in ASN.1 format. It is comprised of a series of tags.

| Code | Value Length | Extra Data                                                                        |
| ---- | :----------: | --------------------------------------------------------------------------------- |
| 0x01 | 1            | None                                                                              |
| 0x0A | 1            | None                                                                              |
| 0x03 | 4            | None                                                                              |
| 0x06 | 4            | None                                                                              |
| 0x04 | 8            | None                                                                              |
| 0x07 | 4            | NUL-terminated ASCII String (of length controlled by dword following 0x07 code)   |
| 0x08 | 4            | NUL-terminated Unicode String (of length controlled by dword following 0x08 code) |
| 0x09 | 4            | Container (of length controlled by dword following 0x09 code)                     |


### Quarantine File Info

The quarantine file info appears to be in ASN.1 format. It is comprised of a series of tags.

| Offset | Length | Field             | Description               |
| ------ | :----: | ----------------- | ------------------------- |
| 0      | 1      | Tag               | ASN.1 tag, always 0x03    |
| 1      | 4      | Tag Value         | Value length of ASN.1 tag |
| 5      | 1      | Tag               | ASN.1 tag, always 0x0A    |
| 6      | 1      | Tag Value         | Value length of ASN.1 tag |
| 7      | 1      | Tag               | ASN.1 tag, always 0x08    |
| 8      | 4      | SHA1 Hash Size    | Size of SHA1              |
| 12     | 82     | SHA1              | SHA1 (Not sure of what)   |
| 94     | 1      | Tag               | ASN.1 tag, always 0x03    |
| 95     | 4      | Tag Value         | Value length of ASN.1 tag |
| 99     | 1      | Tag               | ASN.1 tag, always 0x03    |
| 100    | 4      | Tag Value         | Value length of ASN.1 tag |
| 104    | 1      | Tag               | ASN.1 tag, always 0x09    |
| 105    | 4      | Tage Value Length | dword for container       |
| 109    | 8      | Container         | ?                         |

The next tag determines what comes next. There are two possibilities, 0x08 or 0x09.

#### 0x08 (Optional)

Quarantine File Info continued...

| Offset | Lenght | Field                | Description                 |
| ------ | :----: | -------------------- | --------------------------- |
| 117    | 1      | Tag                  | ASN.1 tag, 0x08             |
| 118    | 4      | SDDL Size            | Variable length             |
| 122    | Varies | SDDL                 | Security descriptor of file |
| Varies | 1      | Tag                  | ASN.1 tag                   |
| Varies | 4      | Tag Value            | Value length of ASN.1 tag   |
| Varies | 1      | Tag                  | ASN.1 tag                   |
| Varies | 8      | Quarantine File Size | Size of quarntine file      |

#### 0x09

##### Quarantine Data

The quarantine file is broken into chunks of data XORed with 0xA5. This continues until the last chunk divider.

| Offset | Lenght | Field                | Description                   |
| ------ | :----: | -------------------- | ----------------------------- |
| 0      | 1      | Tag                  | ASN.1 tag, 0x09               |
| 1      | 4      | Chunk Size           | Variable length               |
| 5      | Varies | Data                 | Quarantine data XORed with A5 |

If the 0x08 tag is not present, there can be two additional structures included with the quarantine data.  
For now, I have labeled them as Junk Header and Junk Footer.

##### Junk Header/Footer (Optional)

| Offset | Lenght | Field            | Description              |
| ------ | :----: | ---------------- | ------------------------ |
| 0      | 8      | Unknown          | ?                        |
| 8      | 8      | Junk Data Size   | Size of junk data        |
| 16     | Varies | Unknown          | ?                        |
| Varies | 12     | Unknonw          | ?                        |
| Varies | 4      | Data Size        | Size of quarantined data |
| Varies | 8      | Unknown          | ?                        |
| Varies | Varies | Data             | Quarantined data         |
| Varies | 8      | Unknown          | ?                        |
| Varies | 8      | Junk Footer Size | Size of junk footer      |
| Varies | 4      | Unknown          | ?                        |
| Varies | Varies | Unknown          | ?                        |

</td></tr> </table>
