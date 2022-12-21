from dissect import cstruct
from helpers.utils import hexdump, flip, progress
from helpers.structures import ASN1_DEF, bb811a3a8fc1be48822c8b6263a5204d_DEF, b91f8a5cb7355c44980325fca1575e71_DEF
import os
import struct
import io
import zlib
import csv
import fileinput
import time

vbnstruct = cstruct.cstruct()
vbnstruct.load(ASN1_DEF)

datastruct = cstruct.cstruct()
datastruct.load(bb811a3a8fc1be48822c8b6263a5204d_DEF)

datastruct2 = cstruct.cstruct()
datastruct2.load(b91f8a5cb7355c44980325fca1575e71_DEF)


def read_sep_tag(_, fname, sub=False, vbn=False, dll=None, hex_dump=False, output='', sonar=False, vbntime=False, total=False, tpos=0):
    _ = io.BytesIO(_)
    report = []
    dd = ''
    sddl = []
    sid = ''
    guid = ''
    dec = ''
    dbguid = ''
    virus = ''
    results = ''
    binary = []
    sonardata = ''
    extradata = []

    cparser = cstruct.cstruct()

    if vbn is True and (time.time() - vbntime) > 1 and not hex_dump:
        progress(tpos, total, status='Parsing Quarantine Metadata')
        report = True

    keys = ['0x5', '0x9', '0xb', '0xc', '0xd', '0x10', '0x12', '0x13', '0x14']
    sub_data = dict.fromkeys(keys)

    checksum_list = [b'\x1d\xb6\ntJ\x8b\xccF\x9d\x82\x86\xf7.\x05Tw',
                     b'y%\xaf\x1f\x14\xed\x91@\xb4\xa7U\x9d\xba%\x06\xfb',
                     b"\xfa\xdb'\xc4L\xb7\xf7J\x8e\xc4\xb0K\xeb\x05\x0bS",
                     b'o\xb4P\xc8nd\x9dN\x80\x86\x9fq\x0cD\xb3|',
                     b'\x0by\x03Y\x9c\xfd\xb7@\xb8\xb6\\~\xf4<\x1b\xd0',
                     b'\xa1\x13\xb3\xc0\xa8.\nL\xa8\x9e)\xf0<q\x1f\xc0',
                     b'\xc4yL{\xa0\xaa\xb8J\x98\x08\x92R\xa9\xbd\xb6\xb2',
                     b'\x91\xd8X\x99\x19\xc3lL\xbe\xb9\xf9\xbf\xb3~\xa4\x93',
                     b'\x82\xceb$\xa9q\x90H\xa1\x15\x0e\nW,\xe6,'
                     ]

    if dll in ('AtpiEim_ReportSubmission', 'ccSubEng', 'SubmissionsEim'):
        data = vbnstruct.ASN1_HEADER(_.read(10))
        dec += hexdump(data.dumps())
        if hex_dump:
            cstruct.dumpstruct(data)
    elif dll == 'IDSxpx86':
        data = vbnstruct.IDSxpx86_HEADER(_.read(49))
        dec += hexdump(data.dumps())
        if hex_dump:
            cstruct.dumpstruct(data)
    elif dll == 'BHSvcPlg':
        data = vbnstruct.BHSvcPlg_HEADER(_.read(27))
        dec += hexdump(data.dumps())
        if hex_dump:
            cstruct.dumpstruct(data)
    else:
        pass

    while _.read(14) == b'\x06\x01\x00\x00\x00\n\x01\n\x00\x06\x01\x00\x00\x00':
        _.seek(-14, 1)
        header = vbnstruct.ASN1_List_Header(_.read(19))
        dec += hexdump(header.dumps())
        if hex_dump:
            cstruct.dumpstruct(header)
        count = 0
        fcount = 0
        set_break = False
        while header.Entries != count:
            repeat = False
            content = None
            list_entry = vbnstruct.ASN1_List_Entry(_.read(7))
            dec += hexdump(list_entry.dumps())
            if hex_dump:
                cstruct.dumpstruct(list_entry)
            if list_entry.Content_Type == 0x1:
                content = vbnstruct.ASN1_1(_.read(2))
            elif list_entry.Content_Type == 0x5:
                content = vbnstruct.ASN1_2(_.read(3))
            elif list_entry.Content_Type == 0x6:
                content = vbnstruct.ASN1_4(_.read(5))
            elif list_entry.Content_Type == 0x7:
                content = vbnstruct.ASN1_4(_.read(5))
            elif list_entry.Content_Type == 0x8:
                content = vbnstruct.ASN1_8(_.read(9))
            elif list_entry.Content_Type == 0x9:
                content = vbnstruct.ASN1_8(_.read(9))
            elif list_entry.Content_Type == 0xb:
                content = vbnstruct.ASN1_16(_.read(17))
                fcount += 1
                if fcount == 1:
                    dbguid = '{' + '-'.join([flip(content.GUID[0:4].hex()),
                                            flip(content.GUID[4:6].hex()),
                                            flip(content.GUID[6:8].hex()),
                                            content.GUID[8:10].hex(),
                                            content.GUID[10:16].hex()]).upper() + '}'
            elif list_entry.Content_Type == 0xc:
                content = vbnstruct.ASN1_16(_.read(17))
            elif list_entry.Content_Type == 0xf:
                _.seek(1, 1)
                size = struct.unpack("<I", _.read(4))[0]
                _.seek(-5, 1)
                content = vbnstruct.ASN1_BLOB(_.read(5 + size))
            elif list_entry.Content_Type == 0x11:
                checksum = vbnstruct.ASN1_GUID(_.read(21))
                dec += hexdump(checksum.dumps())
                if hex_dump:
                    cstruct.dumpstruct(checksum)
                if checksum.GUID == b'!\xa3\x05?\xb7CxE\x93\xc8\xcd\xc5\xf6J\x14\x9a':
                    _.seek(1, 1)
                    size = struct.unpack("<I", _.read(4))[0]
                    _.seek(10, 1)
                    code = struct.unpack("B", _.read(1))[0]
                    _.seek(-16, 1)
                    if code == 7:
                        content = vbnstruct.ID_0x07(_.read(5 + size))
                    elif code == 8:
                        content = vbnstruct.ID_0x08(_.read(5 + size))
                        if list_entry.ID == 0x0 and vbn and len(virus) == 0:
                            virus = content.StringW.replace('\x00', '')
                        if list_entry.ID == 0x1 and vbn:
                            guid = content.StringW.replace('\x00', '')
                        if 'Detection Digest:' in content.StringW and vbn:
                            dd = '\r\n'.join(content.StringW.split('\r\n')[1:]).replace('"', '""')
                        else:
                            extradata.append(content.StringW.replace('\x00', ''))

                elif checksum.GUID == b'\xfd\xa8\xa7aZ\xe1\xcbO\x8a9\xa8\x8b$\xd2\xa7c':
                    _.seek(1, 1)
                    size = struct.unpack("<I", _.read(4))[0]
                    _.seek(-5, 1)
                    content = vbnstruct.ID_0x08_2(_.read(5 + size))
                    sid = content.StringW.replace('\x00', '')
                elif checksum.GUID == b'\xe89\xeb@\xfb\x15\x88D\x9bY,D1\xae\xb5\xd0' or checksum.GUID == b'dE21\x13;3E\x89\x993\x99\x06\x88\xf5\xa9':
                    content = vbnstruct.RAW_DATA(_.read(15))
                    size = content.Data_Length2
                    repeat = True
                elif checksum.GUID == b'\xbf\xcc\\N\xcb\x10\xbcE\x84\xae\x94\x00\x03J\xf8\xc4':
                    GUID_List_header = vbnstruct.GUID_List_Header(_.read(15))
                    dec += hexdump(GUID_List_header.dumps())
                    data = vbnstruct.ASN1_16(_.read(17))
                    dec += hexdump(data.dumps())
                    if hex_dump:
                        cstruct.dumpstruct(GUID_List_header)
                        cstruct.dumpstruct(data)
                    while data.GUID != b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00':
                        ASN1_Unknown_header = vbnstruct.ASN1_Unknown_Header(_.read(31))
                        dec += hexdump(ASN1_Unknown_header.dumps())
                        data = vbnstruct.ASN1_16(_.read(17))
                        dec += hexdump(data.dumps())
                        if hex_dump:
                            cstruct.dumpstruct(ASN1_Unknown_header)
                            cstruct.dumpstruct(data)
                elif checksum.GUID == b'\xbb\x81\x1a:\x8f\xc1\xbeH\x82,\x8bbc\xa5 M':
                    dataheader = datastruct.Header(_.read(21))
                    dec += hexdump(dataheader.dumps())
                    end = _.tell() + dataheader.Data_Length1 - 16
                    if hex_dump:
                        cstruct.dumpstruct(dataheader)
                    while end != _.tell():
                        code = struct.unpack("B", _.read(1))[0]
                        _.seek(-1, 1)
                        if hex(code) == '0x1':
                            datacontent = datastruct.S0x01(_.read(10))
                        elif hex(code) == '0x3':
                            datacontent = datastruct.S0x03(_.read(10))
                        elif hex(code) == '0x4':
                            datacontent = datastruct.S0x04(_.read(14))
                        elif hex(code) == '0x5':
                            _.seek(6, 1)
                            size = struct.unpack("<I", _.read(4))[0]
                            _.seek(-10, 1)
                            datacontent = datastruct.S0x05(_.read(10 + size))
                            extradata.append(datacontent.StringW.replace('\x00', ''))
                        elif hex(code) == '0x6':
                            _.seek(6, 1)
                            size = struct.unpack("<l", _.read(4))[0]
                            _.seek(-10, 1)
                            datacontent = datastruct.S0x06(_.read(10 + size))
                        else:
                            input(f'Error: Unknown datastructure of {hex(code)} in {checksum.GUID}. Please submit an issue to https://github.com/Beercow/SEPparser/issues. Press any key to continue.')
                            pass
                        if hex_dump:
                            cstruct.dumpstruct(datacontent)

                elif checksum.GUID == b'\xb9\x1f\x8a\\\xb75\\D\x98\x03%\xfc\xa1W^q':
                    dataheader2 = datastruct2.Header(_.read(20))
                    _.seek(1, 1)
                    size = struct.unpack("<I", _.read(4))[0]
                    _.seek(-5, 1)
                    virus_name = datastruct2.String(_.read(5 + size))
                    virus = virus_name.StringW.replace('\x00', '')
                    end = dataheader2.Data_Length + _.tell() - virus_name.Size - 20

                    if hex_dump:
                        cstruct.dumpstruct(dataheader2)
                        cstruct.dumpstruct(virus_name)

                    while end != _.tell():
                        code = struct.unpack("B", _.read(1))[0]
                        _.seek(-1, 1)
                        if hex(code) == '0xa':
                            datacontent2 = datastruct2.ASN1_1(_.read(2))
                        elif hex(code) == '0x4':
                            datacontent2 = datastruct2.ASN1_8(_.read(9))
                        elif hex(code) == '0x8':
                            _.seek(1, 1)
                            size = struct.unpack("<I", _.read(4))[0]
                            _.seek(-5, 1)
                            datacontent2 = datastruct2.String(_.read(5 + size))
                            extradata.append(datacontent2.StringW.replace('\x00', ''))
                        elif hex(code) == '0x9':
                            _.seek(5, 1)
                            check = _.read(14)
                            _.seek(-19, 1)

                            if check == b'\x06\x01\x00\x00\x00\n\x01\n\x00\x06\x01\x00\x00\x00':
                                _.seek(1, 1)
                                size = struct.unpack("<I", _.read(4))[0]
                                _.seek(-5, 1)
                                datacontent2 = datastruct2.ASN1_4(_.read(5))
                                if hex_dump:
                                    cstruct.dumpstruct(datacontent2)
                                r = read_sep_tag(_.read(size), fname, vbn=vbn, hex_dump=hex_dump, output=output, vbntime=vbntime, total=total)
                                continue
                            elif check[:-4] == b'\x06\x01\x00\x00\x00\x06\x02\x00\x00\x00':
                                _.seek(1, 1)
                                size = struct.unpack("<I", _.read(4))[0]
                                _.seek(-5, 1)
                                datacontent2 = vbnstruct.ID_0x08(_.read(5 + size))
                                dd = '\r\n'.join(datacontent2.StringW.split('\r\n')[1:]).replace('"', '""')
                            elif check[:-9] == b'\x06\x01\x00\x00\x00':
                                datacontent2 = datastruct2.ASN1_Header(_.read(10))
                            else:
                                _.seek(1, 1)
                                size = struct.unpack("<I", _.read(4))[0]
                                _.seek(-5, 1)
                                if size == 16:
                                    datacontent2 = vbnstruct.ASN1_GUID(_.read(21))
                                else:
                                    datacontent2 = datastruct2.Data(_.read(5 + size))

                        elif hex(code) == '0x6' or hex(code) == '0x3':
                            datacontent2 = datastruct2.ASN1_4(_.read(5))

                        else:
                            input(f'Error: Unknown datastructure of {hex(code)} in {checksum.GUID}. Please submit an issue to https://github.com/Beercow/SEPparser/issues. Press any key to continue.')
                            pass

                        if hex_dump:
                            cstruct.dumpstruct(datacontent2)

                elif checksum.GUID in checksum_list:
                    _.seek(1, 1)
                    size = struct.unpack("<I", _.read(4))[0]
                    _.seek(-5, 1)
                    content = vbnstruct.ASN1_4(_.read(5))
                    repeat = True

                else:
                    _.seek(1, 1)
                    size = struct.unpack("<I", _.read(4))[0]
                    _.seek(-5, 1)
                    content = vbnstruct.ASN1_BLOB(_.read(5 + size))

            else:
                input(f'Error: Unknown Content Type of {list_entry.Content_Type} in file {fname}. Please submit an issue to https://github.com/Beercow/SEPparser/issues. Press any key to continue.')
                pass

            if content:
                if list_entry.ID == 0x23 and checksum.GUID == b'!\xa3\x05?\xb7CxE\x93\xc8\xcd\xc5\xf6J\x14\x9a':
                    sddl.append(content.StringW.replace('\x00', ''))
                dec += hexdump(content.dumps())
                if hex_dump:
                    cstruct.dumpstruct(content)
                if sub:
                    for k in sub_data:
                        if k == hex(list_entry.ID):
                            if hex(list_entry.ID) == '0x5':
                                v = content.StringA.replace(b'\x00', b'').decode('latin-1')
                            else:
                                v = content.StringW.replace('"', '""').replace('\x00', '')
                            sub_data[k] = f'"{v}"'
                if sonar:
                    try:
                        sonardata += content.StringW.replace('\x00', '') + '\n'
                    except:
                        pass

            if repeat is True:
                if sonar:
                    r = read_sep_tag(_.read(size), fname, hex_dump=hex_dump, output=output, sonar=True)
                else:
                    r = read_sep_tag(_.read(size), fname, vbn=vbn, hex_dump=hex_dump, output=output, vbntime=vbntime, total=total, tpos=_.tell())

                if vbn is True:
                    report = r[0]
                dec += r[6]
                dd += r[1]
                sddl.extend(r[2])
                binary.extend(r[9])
                sonardata += r[10]
                extradata.extend(r[11])
                sid += r[3]

            count += 1

            inner_while = _.read(1)
            _.seek(-1, 1)
            if inner_while == b'':
                set_break = True
                break

        stop = _.read(1)

        _.seek(-1, 1)
        if stop == b'' or stop == b'\x00' or set_break is True:
            break

    else:
        if sub is True:
            if struct.unpack("B", _.read(1))[0] != 6:
                return report, dd, sddl, sid, virus, guid, dec, dbguid, results, binary
        _.seek(-14, 1)
        pos = _.tell()
        if dll:
            data_type = _.read(1).hex()
            while data_type == '09':
                size = struct.unpack("<I", _.read(4))[0]
                stringw = _.read(10).hex()
                _.seek(-15, 1)
                if stringw == '06010000000602000000':
                    blob_data = vbnstruct.ID_0x08(_.read(5 + size))
                    binary.append(bytes(blob_data.StringW, 'utf-8'))
                    if 'Report Type' in blob_data.StringW:
                        report.append(blob_data.StringW)
                else:
                    blob_data = vbnstruct.ASN1_BLOB(_.read(5 + size))
                    binary.append(blob_data.dumps())
                dec += hexdump(blob_data.dumps())
                if hex_dump:
                    cstruct.dumpstruct(blob_data)
                data_type = _.read(1).hex()
            _.seek(-1, 1)
            if data_type == '03':
                data = vbnstruct.ASN1_HEADER(_.read(10))
                dec += hexdump(data.dumps())
                if hex_dump:
                    cstruct.dumpstruct(data)
                cparser.load(f"""
                typedef struct _BLOB {{
                    char BLOB[{data.Size}];
                }}; BLOB;
                """)
                blob_data = cparser.BLOB(_.read())
                dec += hexdump(blob_data.dumps())
                binary.append(blob_data.dumps())
                if hex_dump:
                    cstruct.dumpstruct(blob_data)
        else:
            cparser.load(f"""
            typedef struct _BLOB {{
                char BLOB[{_.seek(0, 2) - pos}];
            }}; BLOB;
            """)
            _.seek(pos)
            blob_data = cparser.BLOB(_.read())
            if b'\x00x\xda' in blob_data.dumps()[0:15]:
                if blob_data.dumps().startswith(b'CMPR'):
                    cmpr = zlib.decompress(blob_data.dumps()[8:])
                    cparser.load(f"""
                    typedef struct _NDCA {{
                        char NDCA[{len(cmpr)}];
                    }}; NDCA;
                    typedef struct _Attack_Data {{
                        char Attack_Data[{len(cmpr)}];
                    }}; Attack_Data;
                    """)

                    if cmpr.startswith(b'NDCA'):
                        cmpr_data = cparser.NDCA(cmpr)

                    else:
                        cmpr_data = cparser.Attack_Data(cmpr)

                    if hex_dump:
                        cstruct.dumpstruct(cmpr_data)
                    dec += hexdump(cmpr_data.dumps())
                    binary.append(zlib.decompress(blob_data.dumps()[8:]))
                else:  # SONAR
                    r = read_sep_tag(zlib.decompress(blob_data.dumps()[4:]), fname, hex_dump=hex_dump, sonar=True)
                    dec += r[6]
                    binary.extend(r[9])
                    if os.path.exists(output+'/ccSubSDK/BHSvcPlg.csv'):
                        with fileinput.input(files=(output+'/ccSubSDK/BHSvcPlg.csv'), inplace=True, mode='r') as fn:
                            reader = csv.DictReader(fn)
                            header = '","'.join(reader.fieldnames)
                            print(f'"{header}"')

                            for row in reader:
                                if fname in row['ccSubSDK File GUID']:
                                    row['SONAR'] = r[10]

                                val = '","'.join(str(x).replace('"', '""') for x in row.values())
                                print(f'"{val}"')
            else:
                dec += hexdump(blob_data.dumps())
                if hex_dump:
                    cstruct.dumpstruct(blob_data)
                binary.append(blob_data.dumps())

    results = ','.join(list([str(i or '""') for i in sub_data.values()]))

    if ('' in extradata):
        extradata.remove('')
    if (virus in extradata):
        extradata.remove(virus)
    if (guid in extradata):
        extradata.remove(guid)
    for x in sddl:
        if (x in extradata):
            extradata.remove(x)
    return report, dd, sddl, sid, virus, guid, dec, dbguid, results, binary, sonardata, extradata
