<style>
h1 {
  text-align: center;
}

h2 {
  text-align: center;
}

h3 {
  text-align: center;
}

h4 {
  text-align: center;
}

h5 {
  text-align: center;
}
</style>

<p>
<h1>VBN File Format</h1>
</p>

<table width="1500">
<tr><th><h3>VBN file format V1 (Windows - SEP 11)</h3></th><th><h3>VBN file format V2 (Windows - SEP 12 +)</h3></th><th><h3>VBN file format V2 (Linux - SEP 12 +)</h3></th></tr>
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
| 1408   | 484    | Unknown               | Will require further investigation as to the purpose of this entry.                      |
| 1892   | 48     | Storage Name          | Where threat was found (FileSystem/InternetMail/LotusNotes/MicrosoftExchange)            |
| 1940   | 4      | Storage Instance ID   | Will require further investigation as to the purpose of this entry.                      |
| 1944   | 384    | Storage Key           | Will require further investigation as to the purpose of this entry.                      |
| 2328   | 4      | Data Type             | Value which can describe the subsequent data.                                            |
| 2332   | 4      | Unknown               | Will require further investigation as to the purpose of this entry.                      |
| 2336   | 8      | Unknown               | Will require further investigation as to the purpose of this entry.                      |
| 2344   | 4      | Data Type             | Value which can describe the subsequent data.                                            |
| 2348   | 4      | Quarantine Data Size  | Size of Quarantined Data (bytes)                                                         |
| 2352   | 4      | Date Accessed         | Indicates a time of last access of an object. (Unix: 32 bit Hex)                         |
| 2356   | 4      | Date Modified         | Indicates a time of last modification of content. (Unix: 32 bit Hex)                     |
| 2360   | 4      | Date Created          | Indicates a time of creation of object on the file system. (Unix: 32 bit Hex)            |
| 2364   | 4      | VBin Time             | Time data was quarantined. (Unix: 32 bit Hex)                                            |
| 2368   | 8      | Unknown               | Will require further investigation as to the purpose of this entry.                      |
| 2376   | 16     | Unique ID             | Unique GUID                                                                              |
| 2392   | 260    | Unknown               | Will require further investigation as to the purpose of this entry.                      |
| 2652   | 4      | Unknown               | Will require further investigation as to the purpose of this entry.                      |
| 2656   | 4      | Record Type           | 0x0 = Hybrid, 0x1 = Meta, 0x2 = Quarantine                                               |
| 2660   | 4      | Quarantine Session ID | Name of subfolder where VBN is stored                                                    |
| 2664   | 4      | Remediation Type      | Type of remediation<br><br>0 None<br>2000 Registry<br>2001 File<br>2002 Process<br>2003 Batch File<br>2004 INI File<br>2005 Service<br>2006 Infected File<br>2007 COM Object<br>2008 Host File Entry<br>2009 Directory<br>2010 Layered Service Provider<br>2011 Internet Browser Cache |
| 2668   | 4      | Unknown               | Will require further investigation as to the purpose of this entry.                      |
| 2672   | 4      | Unknown               | Will require further investigation as to the purpose of this entry.                      |
| 2676   | 4      | Unknown               | Will require further investigation as to the purpose of this entry.                      |
| 2680   | 4      | Unknown               | Will require further investigation as to the purpose of this entry.                      |
| 2684   | 4      | Unknown               | Will require further investigation as to the purpose of this entry.                      |
| 2688   | 4      | Unknown               | Will require further investigation as to the purpose of this entry.                      |
| 2692   | 4      | Unknown               | Will require further investigation as to the purpose of this entry.                      |
| 2696   | 768    | Wide Description      | FQP of Quarantine File (Unicode)                                                         |
| 3464   | 212    | Unknown               | Will require further investigation as to the purpose of this entry.                      |

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
| 2472   | 484    | Unknown               | Will require further investigation as to the purpose of this entry.                      |
| 2956   | 48     | Storage Name          | Where threat was found (FileSystem/InternetMail/LotusNotes/MicrosoftExchange)            |
| 3004   | 4      | Storage Instance ID   | Will require further investigation as to the purpose of this entry.                      |
| 3008   | 384    | Storage Key           | Will require further investigation as to the purpose of this entry.                      |
| 3392   | 4      | Data Type             | Value which can describe the subsequent data.                                            |
| 3396   | 4      | Unknown               | Will require further investigation as to the purpose of this entry.                      |
| 3400   | 8      | Unknown               | Will require further investigation as to the purpose of this entry.                      |
| 3408   | 4      | Data Type             | Value which can describe the subsequent data.                                            |
| 3412   | 4      | Quarantine Data Size  | Size of Quarantined Data (bytes)                                                         |
| 3416   | 4      | Date Accessed         | Indicates a time of last access of an object. (Unix: 32 bit Hex)                         |
| 3420   | 4      | Unknown               | Will require further investigation as to the purpose of this entry.                      |
| 3424   | 4      | Date Modified         | Indicates a time of last modification of content. (Unix: 32 bit Hex)                     |
| 3428   | 4      | Unknown               | Will require further investigation as to the purpose of this entry.                      |
| 3432   | 4      | Date Created          | Indicates a time of creation of object on the file system. (Unix: 32 bit Hex)            |
| 3436   | 4      | Unknown               | Will require further investigation as to the purpose of this entry.                      |
| 3440   | 4      | VBin Time             | Time data was quarantined. (Unix: 32 bit Hex)                                            |
| 3444   | 4      | Unknown               | Will require further investigation as to the purpose of this entry.                      |
| 3448   | 4      | Unknown               | Will require further investigation as to the purpose of this entry.                      |
| 3452   | 16     | Unique ID             | Unique GUID                                                                              |
| 3468   | 260    | Unknown               | Will require further investigation as to the purpose of this entry.                      |
| 3728   | 4      | Unknown               | Will require further investigation as to the purpose of this entry.                      |
| 3732   | 4      | Record Type           | 0x0 = Hybrid, 0x1 = Meta, 0x2 = Quarantine                                               |
| 3736   | 4      | Quarantine Session ID | Name of subfolder where VBN is stored                                                    |
| 3740   | 4      | Remediation Type      | Type of remediation<br><br>0 None<br>2000 Registry<br>2001 File<br>2002 Process<br>2003 Batch File<br>2004 INI File<br>2005 Service<br>2006 Infected File<br>2007 COM Object<br>2008 Host File Entry<br>2009 Directory<br>2010 Layered Service Provider<br>2011 Internet Browser Cache |
| 3744   | 4      | Unknown               | Will require further investigation as to the purpose of this entry.                      |
| 3748   | 4      | Unknown               | Will require further investigation as to the purpose of this entry.                      |
| 3752   | 4      | Unknown               | Will require further investigation as to the purpose of this entry.                      |
| 3756   | 4      | Unknown               | Will require further investigation as to the purpose of this entry.                      |
| 3760   | 4      | Unknown               | Will require further investigation as to the purpose of this entry.                      |
| 3764   | 4      | Unknown               | Will require further investigation as to the purpose of this entry.                      |
| 3768   | 4      | Unknown               | Will require further investigation as to the purpose of this entry.                      |
| 3772   | 768    | Wide Description      | FQP of Quarantine File (Unicode)                                                         |
| 4540   | 212    | Unknown               | Will require further investigation as to the purpose of this entry.                      |

</td><td>

<p align="center">
<h3>VBN Metadata &#42WIP</h3>
</p>

| Offset | Length | Field                 | Description                                                                              |
| ------ | :----: | --------------------- | ---------------------------------------------------------------------------------------- |
| 0      | 4      | Size                  | Size of the VBN Metadata section, 0x3afc                                                 |
| 4      | 4096   | Description           | FQP of Quarantine File                                                                   |
| 4100   | 1112   | Log Line              | Information on event.                                                                    |
| 5212   | 4      | Data Type             | Value which can describe the subsequent data. (0x1 = No dates, 0x2 = Dates)              |
| 5216   | 4      | Record ID             | VBin ID/VBN Name                                                                         |
| 5220   | 36     | Unknown               | Will require further investigation as to the purpose of this entry.                      |
| 5256   | 4      | Quarantine File Size  | Size of Quarantined File (bytes)                                                         |
| 5260   | 4      | Date Modified         | Indicates a time of last modification of content. (Unix: 32 bit Hex)                     |
| 5264   | 4      | Date Created          | Indicates a time of creation of object on the file system. (Unix: 32 bit Hex)            |
| 5268   | 4      | Date Accessed         | Indicates a time of last access of an object. (Unix: 32 bit Hex)                         |
| 5272   | 4      | VBin Time             | Time file was quarantined. (Unix: 32 bit Hex)                                            |
| 5276   | 4      | Data Type             | Value which can describe the subsequent data. (0x0 = No storage info, 0x2 = Storage info |
| 5280   | 452    | Unknown               | Will require further investigation as to the purpose of this entry.                      |
| 5732   | 48     | Storage Name          | Appears to always be FileSystem                                                          |
| 5780   | 4      | Storage Instance ID   | Will require further investigation as to the purpose of this entry.                      |
| 5784   | 4096   | Storage Key           | Will require further investigation as to the purpose of this entry.                      |
| 9880   | 4      | Data Type             | Value which can describe the subsequent data.                                            |
| 9884   | 16     | Unknown               | Will require further investigation as to the purpose of this entry.                      |
| 9900   | 36     | Unknown               | Will require further investigation as to the purpose of this entry.                      |
| 9936   | 4      | Quarantine Data Size  | Size of Quarantined Data (bytes)                                                         |
| 9940   | 4      | Date Created          | Indicates a time of creation of object on the file system. (Unix: 32 bit Hex)            |
| 9944   | 4      | Date Accessed         | Indicates a time of last access of an object. (Unix: 32 bit Hex)                         |
| 9948   | 4      | Date Modified         | Indicates a time of last modification of content. (Unix: 32 bit Hex)                     |
| 9952   | 4      | VBin Time             | Time data was quarantined. (Unix: 32 bit Hex)                                            |
| 9956   | 8      | Unknown               | Will require further investigation as to the purpose of this entry.                      |
| 9964   | 16     | Unique ID             | Unique GUID                                                                              |
| 9980   | 4096   | Unknown               | Will require further investigation as to the purpose of this entry.                      |
| 14076  | 4      | Unknown               | Will require further investigation as to the purpose of this entry.                      |
| 14080  | 4      | Record Type           | 0x0 = Hybrid, 0x1 = Meta, 0x2 = Quarantine                                               |
| 14084  | 4      | Quarantine Session ID | Name of subfolder where VBN is stored                                                    |
| 14088  | 4      | Remediation Type      | Type of remediation<br><br>0 None<br>2000 Registry<br>2001 File<br>2002 Process<br>2003 Batch File<br>2004 INI File<br>2005 Service<br>2006 Infected File<br>2007 COM Object<br>2008 Host File Entry<br>2009 Directory<br>2010 Layered Service Provider<br>2011 Internet Browser Cache |
| 14092  | 4      | Unknown               | Will require further investigation as to the purpose of this entry.                      |
| 14096  | 4      | Unknown               | Will require further investigation as to the purpose of this entry.                      |
| 14100  | 4      | Unknown               | Will require further investigation as to the purpose of this entry.                      |
| 14104  | 4      | Unknown               | Will require further investigation as to the purpose of this entry.                      |
| 14108  | 4      | Unknown               | Will require further investigation as to the purpose of this entry.                      |
| 14112  | 4      | Unknown               | Will require further investigation as to the purpose of this entry.                      |
| 14116  | 4      | Unknown               | Will require further investigation as to the purpose of this entry.                      |
| 14120  | 768    | Wide Description      | FQP of Quarantine File (Unicode)                                                         |
| 14888  | 212    | Unknown               | Will require further investigation as to the purpose of this entry.                      |


</td></tr></table>

<p>
<h2>The Record Type determines what comes next.</h2>
</p>

<table width="1750">
<tr><th><h3>Record Type 0<br>The following sections are XORed with 0x5A.</h3></th><th><h3>Record Type 1</h3></th><th><h3>Record Type 2<br>The following sections are XORed with 0x5A.</h3></th></tr>
<tr valign="top"><td>

### QData Location (Optional)

| Offset | Length           | Field                    | Description                                                         |
| ------ | :--------------: | ------------------------ | ------------------------------------------------------------------- |
| 0      | 8                | Header                   | QData location header, 00000006aaaa20ce                                  |
| 8      | 8                | Data Offset              | Offset to start of quarantine data                                  |
| 16     | 8                | Data Size                | Size of quarantine data                                             |
| 24     | 4                | EOF                      | Size from end of quarantine data to EOF                             |
| 28     | Data Offset - 28 | Unknown                  | Will require further investigation as to the purpose of this entry. |

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

### Quarantine Metadata

| Offset | Length  | Field                   | Description                                  |
| ------ | :-----: | ----------------------- | -------------------------------------------- |
| 0      | 8       | QM Header               | Header is always 0000000000000000            |
| 8      | 8       | QM Header Size          | Size, in bytes, of the QM header             |
| 16     | 8       | QM Size                 | Size, in bytes, of the QM                    |
| 24     | 8       | QM Size + Header Size   | Size, in bytes, of the QM and header         |
| 32     | 8       | End of QM to End of VBN | Size, in bytes, from end of QM to end of VBN |
| 40     | QM Size | Quarntine Metadata      | Quarantine Metadata                          |

The quarantine metadata appears to be in ASN.1 format. It is comprised of a series of tags.

### ASN.1 Tags

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


### Quarantine Info

| Offset | Length                      | Field                                  | Description                                                 |
| ------ | :-------------------------: | -------------------------------------- | ----------------------------------------------------------- |
| 0      | 1                           | Tag1                                   | Can be 0x03 or 0x06                                         |
| 1      | 4                           | Tag1 Value                             | Tag1 Value                                                  |
| 5      | 1                           | Tag2                                   | Tag2                                                        |
| 6      | 1                           | Tag2 Value                             | Tag2 Value (value can be 0x00 or 0x01)                      |
| 7      | 1                           | Tag3 (Optional)                        | Tag3 (if Tag2 Value is 0x01, Tag3 can be 0x08 or 0x0A)      | 
| 8      | 4                           | SHA1 Hash Length (Optional)            | Length of SHA1 (if Tag3 is 0x08, data will be present)      |
| 12     | 82                          | SHA1 (Optional)                        | SHA1 of quarantine data                                     |
| 94     | 1                           | Tag4 (Optional)                        | Tag4, always 0x03                                           |
| 95     | 4                           | Tag4 Value (Optional)                  | Tag4 Value                                                  |
| 99     | 1                           | Tag5 (Optional)                        | Tag5, always 0x03                                           |
| 100    | 4                           | Tag5 Value (Optional)                  | Tag5 Value                                                  |
| 104    | 1                           | Tag6 (Optional)                        | Tag6, always 0x09                                           |
| 105    | 4                           | Quarantine Data Size Length (Optional) | Length of quarantine data size                              |
| 109    | Quarantine Data Size Length | Quarantine Data Size (Optional)        | Size of quarantine data                                     |



### Quarantine SDDL (Optional)

Quarantine Info continued... (may not be present)

| Offset | Lenght    | Field                | Description                 |
| ------ | :-------: | -------------------- | --------------------------- |
| 117    | 1         | Tag7                 | Tag7, always 0x08           |
| 118    | 4         | SDDL Size            | Variable length             |
| 122    | SDDL Size | SDDL                 | Security descriptor of file |
| Varies | 1         | Tag8                 | Tag8                        |
| Varies | 4         | Tag8 Value           | Tag8 Value                  |
| Varies | 1         | Tag9                 | Tag9                        |
| Varies | 8         | Quarantine Data Size | Size of quarntine data      |

If the Quarantine SDDL tag is not present, there can be two additional structures included with the quarantine data.  

#### Unknown (Optional)
If the Quarantine Data Size in VBN Metadata is Smaller than the Quarantine Data Size in Quarantine Info, this structure will be present.

| Offset | Lenght                | Field                            | Description                                                         |
| ------ | :-------------------: | -------------------------------- | ------------------------------------------------------------------- |
| 0      | 1                     | Tag                              | ASN.1 tag, 0x09               |
| 0      | 8                     | Unknown                          | Will require further investigation as to the purpose of this entry. |
| 8      | 8                     | Unknown Data Size                | Size of unknown data                                                |
| 16     | Unknown Data Size     | Unknown                          | Will require further investigation as to the purpose of this entry. |
| Varies | 12                    | Unknown                          | Will require further investigation as to the purpose of this entry. |
| Varies | 4                     | Quarantine Data Size             | Size of quarantined data                                            |
| Varies | 8                     | Unknown                          | Will require further investigation as to the purpose of this entry. |


#### Quarantine Data (Optional)

The quarantine data is broken into chunks of data XORed with 0xA5. This continues until the last chunk divider.

| Offset | Lenght     | Field                | Description                   |
| ------ | :--------: | -------------------- | ----------------------------- |
| 0      | 1          | Tag                  | ASN.1 tag, 0x09               |
| 1      | 4          | Chunk Size           | Variable length               |
| 5      | Chunk Size | Data                 | Quarantine data XORed with A5 |

#### Attribute (Optional)

| Offset | Lenght                | Field                            | Description                                                         |
| ------ | :-------------------: | -------------------------------- | ------------------------------------------------------------------- |
| Varies | 8                     | Attribute Data Type (Optional)   | 0x02 = EA, 0x04 = ADS, 0x07 = ?                                     |
| Varies | 8                     | Attribute Data Size (Optional)   | Size of attribute data                                              |
| Varies | 4                     | Attribute Name Size (Optional)   | Size of attribute name field                                        |
| Varies | Attribute Name Size   | Attribute Name (Optional)        | Name of attribute                                                   |
| Varies | Attribute Data Size   | Attribute Data (Optional)        | Data, varies by type                                                |

</td></tr></table>