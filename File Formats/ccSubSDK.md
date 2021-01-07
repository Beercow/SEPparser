# ccSubSDK
Symantec Endpoint Protection clients automatically submit pseudonymous information about detections, network, and configuration to Symantec Security Response. Symantec uses this pseudonymous information to address new and changing threats as well as to improve product performance. Pseudonymous data is not directly identified with a particular user.
The detection information that clients send includes information about antivirus detections, intrusion prevention, SONAR, and file reputation detections.

# submissions.idx
submissions.idx can be found in the following location: C:\ProgramData\Symantec\Symantec Endpoint Protection\CurrentVersion\Data\CmnClnt\ccSubSDK\submissions.idx

## Header

| Offset | Length | Field   | Description                                                         |
| ------ | :----: | ------- | ------------------------------------------------------------------- |
| 0      | 4      | Header  | Always 0x3216144C                                                   |
| 4      | 4      | Unknown | Will require further investigation as to the purpose of this entry. |
| 8      | 4      | Size    | Size of submissions.idx                                             |
| 12     | 4      | Unknown | Will require further investigation as to the purpose of this entry. |
| 16     | 4      | Unknown | Will require further investigation as to the purpose of this entry. |
| 20     | 8      | Unknown | Will require further investigation as to the purpose of this entry. |
| 28     | 20     | Unknown | Will require further investigation as to the purpose of this entry. |

## Index
Continues to end of file.

<table>
    <thead>
        <tr>
            <th>Offset</th>
            <th>Length</th>
            <th>Field</th>
            <th>Description</th>
        </tr>
    </thead>
    <tbody>
        <tr>
            <td>0</td>
            <td>4</td>
            <td>Header</td>
            <td>Always 0x4099C689</td>
        </tr>
        <tr>
            <td>4</td>
            <td>4</td>
            <td>Unknown</td>
            <td>Will require further investigation as to the purpose of this entry.</td>
        </tr>
        <tr>
            <td>8</td>
            <td>8</td>
            <td>Start of Index</td>
            <td>Offset to begining of Index</td>
        </tr>
        <tr>
            <td>16</td>
            <td>8</td>
            <td>Start of Last Index</td>
            <td>Offset to begining of previous Index</td>
        </tr>
        <tr>
            <td>24</td>
            <td>4</td>
            <td>Lenght 1</td>
            <td></td>
        </tr>
        <tr>
            <td>28</td>
            <td>4</td>
            <td>Lenght 2</td>
            <td></td>
        </tr>
        <tr>
            <td>32</td>
            <td>8</td>
            <td>Unknown</td>
            <td>Will require further investigation as to the purpose of this entry.</td>
        </tr>
        <tr>
            <td>40</td>
            <td>16</td>
            <td>Blowfish Key</td>
            <td>Symmetric-key for Blowfish</td>
        </tr>
        <tr>
            <td>56</td>
            <td>Length 1</td>
            <td>Data</td>
            <td>Data appears to be in ASN.1 format. It is comprised of a series of tags.
                <table>
                    <tr>
                        <th>Code</th>
                        <th>Value Length</th>
                        <th>Extra Data</th>
                    </tr>
                    <tr>
                        <td>0x01</td>
                        <td>1</td>
                        <td>None</td>
                    </tr>
                    <tr>
                        <td>0x0A</td>
                        <td>1</td>
                        <td>None</td>
                    </tr>
                    <tr>
                        <td>0x03</td>
                        <td>4</td>
                        <td>None</td>
                    </tr>
                    <tr>
                        <td>0x06</td>
                        <td>4</td>
                        <td>None</td>
                    </tr>
                    <tr>
                        <td>0x04</td>
                        <td>8</td>
                        <td>None</td>
                    </tr>
                    <tr>
                        <td>0x07</td>
                        <td>4</td>
                        <td>NUL-terminated ASCII String (of length controlled by dword following 0x07 code)</td>
                    </tr>
                    <tr>
                        <td>0x08</td>
                        <td>4</td>
                        <td>NUL-terminated Unicode String (of length controlled by dword following 0x08 code)</td>
                    </tr>
                    <tr>
                        <td>0x09</td>
                        <td>4</td>
                        <td>Container (of length controlled by dword following 0x09 code)</td>
                    </tr>
                    <tr>
                        <td>0x0F</td>
                        <td>16</td>
                        <td>None</td>
                    </tr>
                    <tr>
                        <td>0x10</td>
                        <td>16</td>
                        <td>None</td>
                    </tr>
                </table>
            </td>
        </tr>
    </tbody>
</Table>


# \{GUID\} Files

\{GUID\} files can be found in the following location: C:\ProgramData\Symantec\Symantec Endpoint Protection\CurrentVersion\Data\CmnClnt\ccSubSDK\\{GUID\}

<table>
    <thead>
        <tr>
            <th>Offset</th>
            <th>Length</th>
            <th>Field</th>
            <th>Description</th>
        </tr>
    </thead>
    <tbody>
        <tr>
            <td>0</td>
            <td>16</td>
            <td>GUID</td>
            <td>GUID of dll responsible for submission.</td>
        </tr>
        <tr>
            <td>16</td>
            <td>16</td>
            <td>Blowfish Key</td>
            <td>Symmetric-key for Blowfish</td>
        </tr>
        <tr>
            <td>32</td>
            <td>varies</td>
            <td>Data</td>
            <td>Data appears to be in ASN.1 format. It is comprised of a series of tags.
                <table>
                    <tr>
                        <th>Code</th>
                        <th>Value Length</th>
                        <th>Extra Data</th>
                    </tr>
                    <tr>
                        <td>0x01</td>
                        <td>1</td>
                        <td>None</td>
                    </tr>
                    <tr>
                        <td>0x0A</td>
                        <td>1</td>
                        <td>None</td>
                    </tr>
                    <tr>
                        <td>0x03</td>
                        <td>4</td>
                        <td>None</td>
                    </tr>
                    <tr>
                        <td>0x06</td>
                        <td>4</td>
                        <td>None</td>
                    </tr>
                    <tr>
                        <td>0x04</td>
                        <td>8</td>
                        <td>None</td>
                    </tr>
                    <tr>
                        <td>0x07</td>
                        <td>4</td>
                        <td>NUL-terminated ASCII String (of length controlled by dword following 0x07 code)</td>
                    </tr>
                    <tr>
                        <td>0x08</td>
                        <td>4</td>
                        <td>NUL-terminated Unicode String (of length controlled by dword following 0x08 code)</td>
                    </tr>
                    <tr>
                        <td>0x09</td>
                        <td>4</td>
                        <td>Container (of length controlled by dword following 0x09 code)</td>
                    </tr>
                    <tr>
                        <td>0x0F</td>
                        <td>16</td>
                        <td>None</td>
                    </tr>
                    <tr>
                        <td>0x10</td>
                        <td>16</td>
                        <td>None</td>
                    </tr>
                </table>
            </td>
        </tr>
    </tbody>
</Table>