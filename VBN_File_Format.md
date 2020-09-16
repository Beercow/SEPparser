<p>
<h1>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;VBN File Format</h1>
</p>

<table width="1500">
<tr><th><h3>VBN file format V1 (Windows - pre SEP 12)</h3></th><th><h3>VBN file format V2 (Windows - SEP 12 +)</h3></th><th><h3>VBN file format V2 (Linux - SEP 12 +)</h3></th></tr>
<tr valign="top"><td>

<p align="center">
<h3>VBN Metadata</h3>
</p>

| Offset | Length | Field                 | Description                                                                              |
| ------ | :----: | --------------------- | ---------------------------------------------------------------------------------------- |
| 0      | 4      | Size                  | Size of the VBN Metadata section, 0xe5c                                                  |
| 4      | 384    | Description           | FQP of Quarantine File                                                                   |
| 388    | 984    | Log Line              | Information on event.                                                                    |
| 1372   | 4      | Data Type             | Value which can describe the subsequent data. (0x1 = No dates, 0x2 = Dates)              |
| 1376   | 4      | Record ID             | VBin ID/VBN Name                                                                         |
| 1380   | 8      | Date Created          | Indicates a time of creation of object on the file system. (Windows Filetime)            |
| 1388   | 8      | Date Accessed         | Indicates a time of last access of an object. (Windows Filetime)                         |
| 1396   | 8      | Date Modified         | Indicates a time of last modification of content. (Windows Filetime)                     |
| 1404   | 4      | Data Type             | Value which can describe the subsequent data. (0x0 = No storage info, 0x2 = Storage info |
| 1408   | 484    | Unknown               | ?                                                                                        |
| 1892   | 48     | Storage Name          | Where threat was found (FileSystem/InternetMail/LotusNotes/MicrosoftExchange)            |
| 1940   | 4      | Storage Instance ID   | ?                                                                                        |
| 1944   | 384    | Storage Key           | ?                                                                                        |
| 2328   | 4      | Data Type             | Value which can describe the subsequent data.                                            |
| 2332   | 4      | Unknown               | ?                                                                                        |
| 2336   | 8      | Unknown               | ?                                                                                        |
| 2344   | 4      | Data Type             | Value which can describe the subsequent data.                                            |
| 2348   | 4      | Quarantine File Size  | Size of Quarantined File (bytes)                                                         |
| 2352   | 4      | Date Accessed         | Indicates a time of last access of an object. (Unix: 32 bit Hex)                         |
| 2356   | 4      | Date Modified         | Indicates a time of last modification of content. (Unix: 32 bit Hex)                     |
| 2360   | 4      | Date Created          | Indicates a time of creation of object on the file system. (Unix: 32 bit Hex)            |
| 2364   | 4      | VBin Time             | Time file was quarantined. (Unix: 32 bit Hex)                                            |
| 2368   | 8      | Unknown               | ?                                                                                        |
| 2376   | 16     | Unique ID             | Unique GUID                                                                              |
| 2392   | 260    | Unknown               | ?                                                                                        |
| 2652   | 4      | Unknown               | ?                                                                                        |
| 2656   | 4      | Record Type           | 0x0 = Hybrid, 0x1 = Meta, 0x2 = Quarantine                                               |
| 2660   | 4      | Quarantine Session ID | Name of subfolder where VBN is stored                                                    |
| 2664   | 4      | Remediation Type      | Type of remediation                                                                      |
| 2668   | 4      | Unknown               | ?                                                                                        |
| 2672   | 4      | Unknown               | ?                                                                                        |
| 2676   | 4      | Unknown               | ?                                                                                        |
| 2680   | 4      | Unknown               | ?                                                                                        |
| 2684   | 4      | Unknown               | ?                                                                                        |
| 2688   | 4      | Unknown               | ?                                                                                        |
| 2692   | 4      | Unknown               | ?                                                                                        |
| 2696   | 768    | Wide Description      | FQP of Quarantine File (Unicode)                                                         |
| 3464   | 212    | Unknown               | ?                                                                                        |

</td><td>

<p align="center">
<h3>VBN Metadata</h3>
</p>

| Offset | Length | Field                 | Description                                                                              |
| ------ | :----: | --------------------- | ---------------------------------------------------------------------------------------- |
| 0      | 4      | Size                  | Size of the VBN Metadata section, 0x1290                                                 |
| 4      | 384    | Description           | FQP of Quarantine File                                                                   |
| 388    | 2048   | Log Line              | Information on event.                                                                    |
| 2436   | 4      | Data Type             | Value which can describe the subsequent data. (0x1 = No dates, 0x2 = Dates)              |
| 2440   | 4      | Record ID             | VBin ID/VBN Name                                                                         |
| 2444   | 8      | Date Created          | Indicates a time of creation of object on the file system. (Windows Filetime)            |
| 2452   | 8      | Date Accessed         | Indicates a time of last access of an object. (Windows Filetime)                         |
| 2460   | 8      | Date Modified         | Indicates a time of last modification of content. (Windows Filetime)                     |
| 2468   | 4      | Data Type             | Value which can describe the subsequent data. (0x0 = No storage info, 0x2 = Storage info |
| 2472   | 484    | Unknown               | ?                                                                                        |
| 2956   | 48     | Storage Name          | Where threat was found (FileSystem/InternetMail/LotusNotes/MicrosoftExchange)            |
| 3004   | 4      | Storage Instance ID   | ?                                                                                        |
| 3008   | 384    | Storage Key           | ?                                                                                        |
| 3392   | 4      | Data Type             | Value which can describe the subsequent data.                                            |
| 3396   | 4      | Unknown               | ?                                                                                        |
| 3400   | 8      | Unknown               | ?                                                                                        |
| 3408   | 4      | Data Type             | Value which can describe the subsequent data.                                            |
| 3412   | 4      | Quarantine File Size  | Size of Quarantined File (bytes)                                                         |
| 3416   | 8      | Date Accessed         | Indicates a time of last access of an object. (Unix: 32 bit Hex)                         |
| 3424   | 8      | Date Modified         | Indicates a time of last modification of content. (Unix: 32 bit Hex)                     |
| 3432   | 8      | Date Created          | Indicates a time of creation of object on the file system. (Unix: 32 bit Hex)            |
| 3440   | 8      | VBin Time             | Time file was quarantined. (Unix: 32 bit Hex)                                            |
| 3448   | 4      | Unknown               | ?                                                                                        |
| 3452   | 16     | Unique ID             | Unique GUID                                                                              |
| 3468   | 260    | Unknown               | ?                                                                                        |
| 3728   | 4      | Unknown               | ?                                                                                        |
| 3732   | 4      | Record Type           | 0x0 = Hybrid, 0x1 = Meta, 0x2 = Quarantine                                               |
| 3736   | 4      | Quarantine Session ID | Name of subfolder where VBN is stored                                                    |
| 3740   | 4      | Remediation Type      | Type of remediation                                                                      |
| 3744   | 4      | Unknown               | ?                                                                                        |
| 3748   | 4      | Unknown               | ?                                                                                        |
| 3752   | 4      | Unknown               | ?                                                                                        |
| 3756   | 4      | Unknown               | ?                                                                                        |
| 3760   | 4      | Unknown               | ?                                                                                        |
| 3764   | 4      | Unknown               | ?                                                                                        |
| 3768   | 4      | Unknown               | ?                                                                                        |
| 3772   | 768    | Wide Description      | FQP of Quarantine File (Unicode)                                                         |
| 4540   | 212    | Unknown               | ?                                                                                        |

</td><td>

<p align="center">
<h3>VBN Metadata &#42WIP</h3>
</p>

| Offset | Length | Field                 | Description                                                                              |
| ------ | :----: | --------------------- | ---------------------------------------------------------------------------------------- |
| 0      | 4      | Size                  | Size of the VBN Metadata section, 0x3afc                                                 |
| 4      | 4096   | Description           | FQP of Quarantine File                                                                   |
| 4100   | 1112   | Log Line              | Information on event.                                                                    |
| 5121   | 4      | Data Type             | Value which can describe the subsequent data. (0x1 = No dates, 0x2 = Dates)              |
| 5216   | 4      | Record ID             | VBin ID/VBN Name                                                                         |
| 5220   | 40     | Unknown               | ?                                                                                        |
| 5260   | 4      | Date Modified         | Indicates a time of last modification of content. (Unix: 32 bit Hex)                     |
| 5264   | 4      | Date Created          | Indicates a time of creation of object on the file system. (Unix: 32 bit Hex)            |
| 5268   | 4      | Date Accessed         | Indicates a time of last access of an object. (Unix: 32 bit Hex)                         |
| 5272   | 4      | VBin Time             | Time file was quarantined. (Unix: 32 bit Hex)                                            |
| 5276   | 4      | Data Type             | Value which can describe the subsequent data. (0x0 = No storage info, 0x2 = Storage info |
| 5280   | 452    | Unknown               | ?                                                                                        |
| 5732   | 48     | Storage Name          | Appears to always be FileSystem                                                          |
| 5780   | 4      | Storage Instance ID   | ?                                                                                        |
| 5784   | 4096   | Storage Key           | ?                                                                                        |
| 9880   | 4      | Data Type             | Value which can describe the subsequent data.                                            |
| 9884   | 4      | Unknown               | ?                                                                                        |
| 9888   | 44     | Unknown               | ?                                                                                        |
| 9932   | 4      | Data Type             | Value which can describe the subsequent data.                                            |
| 9936   | 4      | Quarantine File Size  | Size of Quarantined File (bytes)                                                         |
| 9940   | 4      | Date Created          | Indicates a time of creation of object on the file system. (Unix: 32 bit Hex)            |
| 9944   | 4      | Date Accessed         | Indicates a time of last access of an object. (Unix: 32 bit Hex)                         |
| 9948   | 4      | Date Modified         | Indicates a time of last modification of content. (Unix: 32 bit Hex)                     |
| 9952   | 4      | VBin Time             | Time file was quarantined. (Unix: 32 bit Hex)                                            |
| 9956   | 8      | Unknown               | ?                                                                                        |
| 9964   | 16     | Unique ID             | Unique GUID                                                                              |
| 9980   | 4096   | Unknown               | ?                                                                                        |
| 14076  | 4      | Unknown               | ?                                                                                        |
| 14080  | 4      | Record Type           | 0x0 = Hybrid, 0x1 = Meta, 0x2 = Quarantine                                               |
| 14084  | 4      | Quarantine Session ID | Name of subfolder where VBN is stored                                                    |
| 14088  | 4      | Remediation Type      | Type of remediation                                                                      |
| 14092  | 4      | Unknown               | ?                                                                                        |
| 14096  | 4      | Unknown               | ?                                                                                        |
| 14100  | 4      | Unknown               | ?                                                                                        |
| 14104  | 4      | Unknown               | ?                                                                                        |
| 14108  | 4      | Unknown               | ?                                                                                        |
| 14112  | 4      | Unknown               | ?                                                                                        |
| 14116  | 4      | Unknown               | ?                                                                                        |
| 14120  | 768    | Wide Description      | FQP of Quarantine File (Unicode)                                                         |
| 14888  | 212    | Unknown               | ?                                                                                        |


</td></tr></table>

<p>
<h5>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;The following sections are XORed with 0x5A. The Record Type determines what comes next.</h5>
</p>

<table width="1500">
<tr><th><h3>Record Type 0</h3></th><th><h3>Record Type 1</h3></th><th><h3>Record Type 2</h3></th></tr>
<tr valign="top"><td>

### QData Location (Optional)

| Offset | Length           | Field                    | Description                             |
| ------ | :--------------: | ------------------------ | --------------------------------------- |
| 0      | 8                | Header                   | QData location header, 0x6aaaa20ce      |
| 8      | 8                | Data Offset              | Offset to start of quarantine data      |
| 16     | 8                | Data Size                | Size of quarantine data                 |
| 24     | 4                | EOF                      | Size from end of quarantine data to EOF |
| 28     | Data Offset - 28 | Unknown                  | ?                                       |

### Quarantine Data

| Offset | Length | Field | Description     |
| ------ | :----: | ----- | --------------- |
| 0      | Varies | Data  | Quarantine data |

### QData Info (Optional)

| Offset | Length               | Field           | Description                                      |
| ------ | :------------------: | --------------- | ------------------------------------------------ |
| 0      | 8                    | Header          | QData info header                                |
| 8      | 8                    | QData Info Size | Size of QData info                               |
| 16     | QData Info Size - 16 | QData           | Additional information about the quarantine data |

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
| 0x0F | 16           | None                                                                              |
| 0x10 | 16           | None                                                                              |

</td><td>

### Quarantine File Metadata Header

| Offset | Length   | Field                    | Description                                   |
| ------ | :------: | ------------------------ | --------------------------------------------- |
| 0      | 8        | QFM Header               | Header is always 0000000000000000             |
| 8      | 8        | QFM Header Size          | Size, in bytes, of the QFM header             |
| 16     | 8        | QFM Size                 | Size, in bytes, of the QFM                    |
| 24     | 8        | QFM Size + Header Size   | Size, in bytes, of the QFM and header         |
| 32     | 8        | End of QFM to End of VBN | Size, in bytes, from end of QFM to end of VBN |
| 40     | QFM Size | Quarntine File Metadata  | Quarantine File Metadata                      |

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
| 0x0F | 16           | None                                                                              |
| 0x10 | 16           | None                                                                              |


### Quarantine File Info

The quarantine file info appears to be in ASN.1 format. It is comprised of a series of tags.

| Offset | Length | Field                                  | Description               |
| ------ | :----: | -------------------------------------- | ----------------------------------------------------------- |
| 0      | 1      | Tag1                                   | ASN.1 tag (can be 0x03 or 0x06)                             |
| 1      | 4      | Tag1 Value                             | Value length of ASN.1 tag                                   |
| 5      | 1      | Tag2                                   | ASN.1 tag                                                   |
| 6      | 1      | Tag2 Value                             | Value length of ASN.1 tag (value can be 0x00 or 0x01)       |
| 7      | 1      | Tag3 (Optional)                        | ASN.1 tag (if Tag2 Value is 0x01, Tag3 can be 0x08 or 0x0A) | 
| 8      | 4      | SHA1 Hash Length (Optional)            | Length of SHA1 (if Tag3 is 0x08, data will be present)      |
| 12     | 82     | SHA1 (Optional)                        | SHA1 (Not sure of what)                                     |
| 94     | 1      | Tag4 (Optional)                        | ASN.1 tag, always 0x03                                      |
| 95     | 4      | Tag4 Value (Optional)                  | Value length of ASN.1 tag                                   |
| 99     | 1      | Tag5 (Optional)                        | ASN.1 tag, always 0x03                                      |
| 100    | 4      | Tag5 Value (Optional)                  | Value length of ASN.1 tag                                   |
| 104    | 1      | Tag6 (Optional)                        | ASN.1 tag, always 0x09                                      |
| 105    | 4      | Quarantine Data Size Length (Optional) | Length of quarantine data size                              |
| 109    | 8      | Quarantine Data Size (Optional)        | Size of quarantine data                                     |

The next tag determines what comes next. There are two possibilities, 0x08 or 0x09.

#### 0x08 (Optional)

Quarantine File Info continued...

| Offset | Lenght    | Field                | Description                 |
| ------ | :-------: | -------------------- | --------------------------- |
| 117    | 1         | Tag                  | ASN.1 tag, 0x08             |
| 118    | 4         | SDDL Size            | Variable length             |
| 122    | SDDL Size | SDDL                 | Security descriptor of file |
| Varies | 1         | Tag                  | ASN.1 tag                   |
| Varies | 4         | Tag Value            | Value length of ASN.1 tag   |
| Varies | 1         | Tag                  | ASN.1 tag                   |
| Varies | 8         | Quarantine Data Size | Size of quarntine data      |

#### 0x09

##### Quarantine Data

The quarantine file is broken into chunks of data XORed with 0xA5. This continues until the last chunk divider.

| Offset | Lenght     | Field                | Description                   |
| ------ | :--------: | -------------------- | ----------------------------- |
| 0      | 1          | Tag                  | ASN.1 tag, 0x09               |
| 1      | 4          | Chunk Size           | Variable length               |
| 5      | Chunk Size | Data                 | Quarantine data XORed with A5 |

If the 0x08 tag is not present, there can be two additional structures included with the quarantine data.  
For now, I have labeled them as Junk Header and Junk Footer.

##### Junk Header/Footer (Optional)

| Offset | Lenght                | Field                            | Description                    |
| ------ | :-------------------: | -------------------------------- | ------------------------------ |
| 0      | 8                     | Unknown                          | ?                              |
| 8      | 8                     | Junk Data Size                   | Size of junk data              |
| 16     | Junk Data Size        | Unknown                          | ?                              |
| Varies | 12                    | Unknown                          | ?                              |
| Varies | 4                     | Quarantine Data Size             | Size of quarantined data       |
| Varies | 8                     | Unknown                          | ?                              |
| Varies | Quarantine Data Size  | Quarantine Data                  | Quarantined data               |
| Varies | 8                     | Junk Footer Data Type (Optional) | 0x02 = ?, 0x04 = ADS, 0x07 = ? |
| Varies | 8                     | Junk Footer Data Size (Optional) | Size of junk footer data       |
| Varies | 4                     | ADS Name Size (Optional)         | Size of ADS name field         |
| Varies | ADS Name Size         | ADS Name (Optional)              | Name of Alternate Data Stream  |
| Varies | Junk Footer Data Size | Junk Footer Data (Optional)      | Data, varies by type           |

</td></tr></table>