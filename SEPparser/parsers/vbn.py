import os
import struct
import hashlib
import time
import parsers.logline as logline
import parsers.ASN1 as ASN1
import parsers.SDDL3 as SDDL3
import helpers.utils as utils
from dissect import cstruct
from datetime import datetime
from manuf import manuf
from helpers.structures import VBN_DEF
import helpers.enums as enums


vbnstruct = cstruct.cstruct()
vbnstruct.load(VBN_DEF)


def xor(msg, key):
    return ''.join(chr(key ^ j) for j in msg)


def attrib_type(_):

    attid = {
             2: '$EA',
             4: '$DATA',
             7: '$OBJECT_ID'
            }

    for k, v in attid.items():

        if k == _:
            return v


def splitCount(s, count):
    return ':'.join(s[i:i+count] for i in range(0, len(s), count))


def from_filetime(_):

    if _ == 0:
        _ = datetime(1601, 1, 1).strftime('%Y-%m-%d %H:%M:%S')

    else:
        _ = datetime.utcfromtimestamp(float(_ - 116444736000000000) / 10000000).strftime('%Y-%m-%d %H:%M:%S.%f')

    return _


def sddl_translate(string):
    target = 'service'
    _ = string + '\n\n'
    sec = SDDL3.SDDL(string, target)

    if sec.owner_sid:
        _ += '\tOwner Name: ' + sec.owner_account + '\n'
        _ += '\tOwner SID: ' + sec.owner_sid + '\n\n'

    if sec.group_sid:
        _ += '\tGroup Name: ' + sec.group_account + '\n'
        _ += '\tGroup SID: ' + sec.group_sid + '\n\n'

    if sec.sddl_dacl:
        if sec.dacl_flags:
            _ += 'Type: ' + sec.sddl_dacl + str(sec.dacl_flags) + '\n'

        else:
            _ += 'Type: ' + sec.sddl_dacl + '\n'

        _ = acl_translate(_, sec.dacl)

    if sec.sddl_sacl:
        if sec.sacl_flags:
            _ += 'Type: ' + sec.sddl_sacl + str(sec.sacl_flags) + '\n'

        else:
            _ += 'Type: ' + sec.sddl_sacl + '\n'

        _ = acl_translate(_, sec.sacl)

    _ += f'\n{"=" * 100}\n'

    return _


def acl_translate(_, acl):
    count = 0
    for ace in acl:
        _ += '\tAce[{:02d}]'.format(count) + '\n'
        _ += '\t\tACE Type: ' + ace.ace_type + '\n'

        if ace.flags:
            _ += '\t\tAce Flags:\n'

            for flag in ace.flags:
                _ += '\t\t\t' + flag + '\n'

        _ += '\t\tAccess Mask:\n'

        for perm in ace.perms:
            _ += '\t\t\t' + perm + '\n'

        if ace.object_type:
            _ += '\t\tObject GUID: ' + ace.object_type + '\n'

        if ace.inherited_type:
            _ += '\t\tInherited Object GUID: ' + ace.inherited_type + '\n'
        _ += '\t\tTrustee: ' + ace.trustee + '\n'
        _ += '\t\tAce Sid: ' + ace.sid + '\n'
        count += 1

    return _


def parse_vbn(f, logType, tz, hex_dump, quarantine_dump, hash_file, extract, output):
    total = f.seek(0, os.SEEK_END)
    vbin = ''  # linux
    qfile = ''
    sddl = []
    sddls = ''
    sha1 = ''
    qds2 = ''
    qds3 = ''
    attribType = ''
    dd = ''
    extradata = ''
    sid = ''
    virus = ''
    guid = ''
    attribData = ''
    qfile_actual_md5 = ''
    qfile_actual_sha1 = ''
    qfile_actual_sha256 = ''
    qfs = 0
    extraData = None
    header = 0
    footer = 0
    qdl = False
    f.seek(0, 0)
    qm_offset = struct.unpack('i', f.read(4))[0]
    f.seek(0, 0)

    if logType == 7:
        f.seek(388, 0)
        logEntry = f.read(2048).split(b'\x00\x00')[0]

    if logType == 8:
        f.seek(4100, 0)
        logEntry = f.read(1112).split(b'\x00\x00')[0]

    logEntry = logline.read_log_data(logEntry, tz)
    f.seek(0, 0)

    if qm_offset == 3676:
        vbnmeta = vbnstruct.VBN_METADATA_V1(f)

    if qm_offset == 4752:
        vbnmeta = vbnstruct.VBN_METADATA_V2(f)

    if qm_offset == 15100:
        vbnmeta = vbnstruct.VBN_METADATA_Linux(f)

    if qm_offset == 15108:
        vbnmeta = vbnstruct.VBN_METADATA_Linux_V2(f)

    wDescription = vbnmeta.WDescription.rstrip('\0')
    description = vbnmeta.Description.rstrip(b'\x00').decode("utf-8", "ignore")
    storageName = vbnmeta.Storage_Name.rstrip(b'\x00').decode("utf-8", "ignore")
    storageKey = vbnmeta.Storage_Key.rstrip(b'\x00').decode("utf-8", "ignore")
    uniqueId = '{' + '-'.join([utils.flip(vbnmeta.Unique_ID.hex()[:8]), utils.flip(vbnmeta.Unique_ID.hex()[8:12]), utils.flip(vbnmeta.Unique_ID.hex()[12:16]), vbnmeta.Unique_ID.hex()[16:20], vbnmeta.Unique_ID.hex()[20:32]]).upper() + '}'

    if hex_dump:
        cstruct.dumpstruct(vbnmeta)

    if vbnmeta.Record_Type == 0:
        try:
            qds2 = vbnmeta.Quarantine_Data_Size_2

        except:
            pass

        qdl = xor(f.read(8), 0x5A).encode('latin-1').hex()

        if qdl == 'ce20aaaa06000000':
            if hex_dump:
                print('\n           #######################################################')
                print('           #######################################################')
                print('           ##                                                   ##')
                print('           ## The following data structures are xored with 0x5A ##')
                print('           ##                                                   ##')
                print('           #######################################################')
                print('           #######################################################\n')
            qdata_location_size = xor(f.read(4), 0x5A).encode('latin-1')
            qdata_location_size = struct.unpack('i', qdata_location_size)[0]
            f.seek(-12, 1)
            qdata_location = vbnstruct.QData_Location(xor(f.read(qdata_location_size), 0x5A).encode('latin-1'))

            if hex_dump:
                cstruct.dumpstruct(qdata_location)

            pos = vbnmeta.QM_HEADER_Offset + qdata_location.Quarantine_Data_Offset
            file_size = qdata_location.QData_Location_Size - qdata_location.Quarantine_Data_Offset
            f.seek(pos)

            if extract:
                print('\n           #######################################################')
                print('           #######################################################')
                print('           ##                                                   ##')
                print('           ##    Extracting quarantine file. Please wait....    ##')
                print('           ##                                                   ##')
                print('           #######################################################')
                print('           #######################################################\n')

            if extract or quarantine_dump or hash_file:
                qfile = xor(f.read(file_size), 0x5A)

            f.seek(pos + file_size)
            # need to properly parse
            qdata_info = vbnstruct.QData_Info(xor(f.read(), 0x5A).encode('latin-1'))

            if hex_dump:
                cstruct.dumpstruct(qdata_info)

        else:
            f.seek(-8, 1)

            if extract or quarantine_dump or hash_file:
                qfile = xor(f.read(), 0x5A)

    if vbnmeta.Record_Type == 1:
        total = total - qm_offset
        if hex_dump:
            print('\n           #######################################################')
            print('           #######################################################')
            print('           ##                                                   ##')
            print('           ##            Quarantine Metadata (ASN.1)            ##')
            print('           ##                                                   ##')
            print('           #######################################################')
            print('           #######################################################\n')

        tags, dd, sddl, sid, virus, guid, dec, dbguid, results, binary, sonardata, extradata = ASN1.read_sep_tag(f.read(), f.name, vbn=True, hex_dump=hex_dump, vbntime=time.time(), total=total)
        if tags:
            print('\n')

        if extract or quarantine_dump:
            print(f'\033[1;31mRecord type 1 does not contain quarantine data.\033[1;0m\n')

    if vbnmeta.Record_Type == 2:
        f.seek(vbnmeta.QM_HEADER_Offset, 0)
        f.seek(8, 1)
        qm_size = xor(f.read(8), 0x5A).encode('latin-1')
        qm_size = struct.unpack('q', qm_size)[0]
        f.seek(-16, 1)
        qmh = vbnstruct.Quarantine_Metadata_Header(xor(f.read(qm_size), 0x5A).encode('latin-1'))

        if hex_dump:
            print('\n           #######################################################')
            print('           #######################################################')
            print('           ##                                                   ##')
            print('           ## The following data structures are xored with 0x5A ##')
            print('           ##                                                   ##')
            print('           #######################################################')
            print('           #######################################################\n')

            cstruct.dumpstruct(qmh)

            print('\n           #######################################################')
            print('           #######################################################')
            print('           ##                                                   ##')
            print('           ##            Quarantine Metadata (ASN.1)            ##')
            print('           ##                                                   ##')
            print('           #######################################################')
            print('           #######################################################\n')

        tags, dd, sddl, sid, virus, guid, dec, dbguid, results, bianry, sonardata, extradata = ASN1.read_sep_tag(xor(f.read(qmh.QM_Size), 0x5A).encode('latin-1'), f.name, vbn=True, hex_dump=hex_dump, vbntime=time.time(), total=qmh.QM_Size)
        if tags:
            print('\n')

        pos = qmh.QM_Size_Header_Size + vbnmeta.QM_HEADER_Offset
        f.seek(pos)
        dataType = int.from_bytes(xor(f.read(1), 0x5A).encode('latin-1'), 'little')
        f.seek(pos)

        if dataType == 3:
            qi = vbnstruct.Quarantine_Hash(xor(f.read(7), 0x5A).encode('latin-1'))

            if hex_dump:
                cstruct.dumpstruct(qi)

            if qi.Tag2_Data == 1:
                qhc = vbnstruct.Quarantine_Hash_Continued(xor(f.read(110), 0x5A).encode('latin-1'))
                sha1 = qhc.SHA1.replace("\x00", "")
                qds2 = int.from_bytes(qhc.Quarantine_Data_Size_2, 'little')

                if hex_dump:
                    cstruct.dumpstruct(qhc)

            try:
                dataType = int.from_bytes(xor(f.read(1), 0x5A).encode('latin-1'), 'little')

                if dataType == 8:
                    pos += 35 + qhc.SHA1_Hash_Length
                    f.seek(pos)
                    qsddl_size = struct.unpack('i', xor(f.read(4), 0x5A).encode('latin-1'))[0] + 18
                    f.seek(-4, 1)
                    qsddl = vbnstruct.Quarantine_SDDL(xor(f.read(qsddl_size), 0x5A).encode('latin-1'))

                    sddl.append(qsddl.Security_Descriptor.replace("\x00", ""))
                    qds3 = qsddl.Quarantine_Data_Size_3

                    if hex_dump:
                        cstruct.dumpstruct(qsddl)

                    pos += 19 + qsddl.Security_Descriptor_Size
                    f.seek(pos)

                if dataType == 9:
                    extraData = qds2 - vbnmeta.Quarantine_Data_Size
                    pos += 35 + qhc.SHA1_Hash_Length
                    f.seek(pos)

                chunk = vbnstruct.Chunk(xor(f.read(5), 0x5A).encode('latin-1'))
                pos += 5
                f.seek(pos)

                if extraData is not None:
                    uh = vbnstruct.Unknown_Header(xor(f.read(1000), 0xA5).encode('latin-1'))
                    header = uh.Size + 40
                    footer = extraData - header

                    if hex_dump:
                        cstruct.dumpstruct(uh)

                    f.seek(pos)

                if hex_dump or extract or quarantine_dump or hash_file:
                    while True:
                        if chunk.Data_Type == 9:

                            if hex_dump:
                                cstruct.dumpstruct(chunk)

                            qfile += xor(f.read(chunk.Chunk_Size), 0xA5)

                            try:
                                pos += chunk.Chunk_Size
                                chunk = vbnstruct.Chunk(xor(f.read(5), 0x5A).encode('latin-1'))
                                pos += 5
                                f.seek(pos)

                            except:
                                break

                        else:
                            break

                if extraData is not None:
                    qfs = qds2 - footer
                    f.seek(-footer, 2)

                    try:
                        attribType = attrib_type(int.from_bytes(xor(f.read(1), 0xA5).encode('latin-1'), 'little'))

                        if f.read(1) == b'':
                            attribType = ''

                        f.seek(-2, 1)

                        if attribType == '$EA':
                            ea1 = vbnstruct.Extended_Attribute(xor(f.read(20), 0xA5).encode('latin-1'))

                            if hex_dump:
                                cstruct.dumpstruct(ea1)

                            while True:
                                neo = int.from_bytes(xor(f.read(4), 0xA5).encode("latin-1"), "little")
                                f.seek(1, 1)
                                nl = int.from_bytes(xor(f.read(1), 0xA5).encode("latin-1"), "little")
                                vl = int.from_bytes(xor(f.read(2), 0xA5).encode("latin-1"), "little")
                                f.seek(-8, 1)
                                neo2 = nl + vl + 8
                                neo3 = neo - neo2 - 1
                                ea = vbnstruct.FILE_FULL_EA_INFORMATION(xor(f.read(neo2 + 1), 0xA5).encode('latin-1'))

                                eaname = ea.EaName.decode('latin-1')
                                eavalue = ea.EaValue.hex()[(56 - nl) * 2:]

                                if eaname == "$KERNEL.PURGE.APPID.VERSIONINFO":
                                    eavalue = bytes.fromhex(eavalue).decode('latin-1')[::2]
                                attribData += (f'{eaname}\n{eavalue}\n\n')

                                if hex_dump:
                                    cstruct.dumpstruct(ea)

                                if ea.NextEntryOffset == 0:
                                    break

                                f.seek(neo3, 1)

                        elif attribType == '$DATA':
                            ads = vbnstruct.ADS_Attribute(xor(f.read(footer), 0xA5).encode('latin-1'))

                            adsname = ads.ADS_Name.replace(b'\x00', b'').decode('latin-1')
                            adsdata = ads.Data.replace(b'\x00', b'').decode('latin-1')
                            attribData = (f'{adsname}\n\n{adsdata}')

                            if hex_dump:
                                cstruct.dumpstruct(ads)

                        elif attribType == '$OBJECT_ID':
                            oi = vbnstruct.OBJECT_ID_Attribute(xor(f.read(footer), 0xA5).encode('latin-1'))

                            guid1 = '-'.join([utils.flip(oi.GUID_Object_Id.hex()[0:8]), utils.flip(oi.GUID_Object_Id.hex()[8:12]), utils.flip(oi.GUID_Object_Id.hex()[12:16]), oi.GUID_Object_Id.hex()[16:20], oi.GUID_Object_Id.hex()[20:32]])

                            guid2 = '-'.join([utils.flip(oi.GUID_Birth_Volume_Id.hex()[0:8]), utils.flip(oi.GUID_Birth_Volume_Id.hex()[8:12]), utils.flip(oi.GUID_Birth_Volume_Id.hex()[12:16]), oi.GUID_Birth_Volume_Id.hex()[16:20], oi.GUID_Birth_Volume_Id.hex()[20:32]])

                            guid3 = '-'.join([utils.flip(oi.GUID_Birth_Object_Id.hex()[0:8]), utils.flip(oi.GUID_Birth_Object_Id.hex()[8:12]), utils.flip(oi.GUID_Birth_Object_Id.hex()[12:16]), oi.GUID_Birth_Object_Id.hex()[16:20], oi.GUID_Birth_Object_Id.hex()[20:32]])

                            guid4 = '-'.join([utils.flip(oi.GUID_Domain_Id.hex()[0:8]), utils.flip(oi.GUID_Domain_Id.hex()[8:12]), utils.flip(oi.GUID_Domain_Id.hex()[12:16]), oi.GUID_Domain_Id.hex()[16:20], oi.GUID_Domain_Id.hex()[20:32]])

                            uuid = int(''.join([utils.flip(oi.GUID_Birth_Object_Id.hex()[12:16]), utils.flip(oi.GUID_Birth_Object_Id.hex()[8:12]), utils.flip(oi.GUID_Birth_Object_Id.hex()[0:8])])[1:], 16)
                            guidtime = datetime.utcfromtimestamp((uuid - 0x01b21dd213814000)*100/1e9)

                            guidmac = splitCount(oi.GUID_Birth_Object_Id.hex()[20:32], 2)
                            p = manuf.MacParser()
                            macvendor = p.get_manuf_long(guidmac)

                            if macvendor is None:
                                macvendor = "(Unknown vendor)"

                            attribData = (f'MAC Address: {guidmac}\nMAC Vendor: {macvendor}\nCreation: {guidtime}\n\nObject ID: {guid1}\nBirth Volume ID: {guid2}\nBirth Object ID: {guid3}\nDomain ID: {guid4}')

                            if hex_dump:
                                cstruct.dumpstruct(oi)

                        else:
                            unknown = vbnstruct.Unknown_Attribute(xor(f.read(footer), 0xA5).encode('latin-1'))

                            if hex_dump:
                                cstruct.dumpstruct(unknown)

                    except:
                        pass

            except:
                if extract:
                    print(f'\033[1;31mDoes not contain quarantine data. Clean by Deletion.\033[1;0m\n')
                    print(f'\033[1;32mFinished parsing {f.name} \033[1;0m\n')

                pass

        if dataType == 6:
            if hex_dump:
                print('\n           #######################################################')
                print('           #######################################################')
                print('           ##                                                   ##')
                print('           ##           Quarantine Metadata 2 (ASN.1)           ##')
                print('           ##                                                   ##')
                print('           #######################################################')
                print('           #######################################################\n')
                ASN1.read_sep_tag(xor(f.read(), 0x5A).encode('latin-1'), f.name, vbn=True, hex_dump=hex_dump)

    if len(qfile) > 0 and hash_file:
        if (header or qfs) == 0:
            qfile_actual_md5 = hashlib.md5(qfile.encode('latin-1')).hexdigest()
            qfile_actual_sha1 = hashlib.sha1(qfile.encode('latin-1')).hexdigest()
            qfile_actual_sha256 = hashlib.sha256(qfile.encode('latin-1')).hexdigest()
        else:
            qfile_actual_md5 = hashlib.md5(qfile[header:qfs].encode('latin-1')).hexdigest()
            qfile_actual_sha1 = hashlib.sha1(qfile[header:qfs].encode('latin-1')).hexdigest()
            qfile_actual_sha256 = hashlib.sha256(qfile[header:qfs].encode('latin-1')).hexdigest()

        if vbnmeta.Record_Type == 0:
            print(f'\033[1;37mSHA1({qfile_actual_sha1}) of the quarantined data.\033[1;0m\n')

        elif sha1.lower() != qfile_actual_sha1.lower():
            print(f'\033[1;37mActual SHA1({qfile_actual_sha1}) of the quarantined data does not match stated SHA1({sha1})!\033[1;0m\n')

        else:
            print(f'\033[1;37mQuarantine data hash verified.\033[1;0m\n')

    if quarantine_dump and len(qfile) > 0:
        if (header or qfs) == 0:
            print(utils.hexdump(qfile.encode('latin-1')))

        else:
            print(utils.hexdump(qfile[header:qfs].encode('latin-1')))

    if extract and len(qfile) > 0:
        output = open(output + '/' + os.path.basename(description) + '.vbn', 'wb+')

        if (header or qfs) == 0:
            output.write(bytes(qfile, encoding='latin-1'))

        else:
            output.write(bytes(qfile[header:qfs], encoding='latin-1'))
        print(output.name)
    if not (extract or hex_dump):
        try:
            modify = from_filetime(vbnmeta.Date_Modified)
            create = from_filetime(vbnmeta.Date_Created)
            access = from_filetime(vbnmeta.Date_Accessed)
            vbin = 'Linux Only'

        except:
            modify = utils.from_unix_sec(vbnmeta.Date_Modified)
            create = utils.from_unix_sec(vbnmeta.Date_Created)
            access = utils.from_unix_sec(vbnmeta.Date_Accessed)
            vbin = utils.from_unix_sec(vbnmeta.VBin_Time)

        attribData = attribData.replace('"', '""')

        for x in sddl:
            sddls += sddl_translate(x)

        return (f'"{f.name}","{virus}","{description}","{vbnmeta.Record_ID}","{create}","{access}","{modify}","{vbin}","{storageName}","{vbnmeta.Storage_Instance_ID}","{storageKey}","{vbnmeta.Quarantine_Data_Size}","{utils.from_unix_sec(vbnmeta.Date_Created_2)}","{utils.from_unix_sec(vbnmeta.Date_Accessed_2)}","{utils.from_unix_sec(vbnmeta.Date_Modified_2)}","{utils.from_unix_sec(vbnmeta.VBin_Time_2)}","{uniqueId}","{vbnmeta.Record_Type}","{hex(vbnmeta.Quarantine_Session_ID)[2:].upper()}","{enums.remediation_type_desc.get(vbnmeta.Remediation_Type, vbnmeta.Remediation_Type)}","{wDescription}","{sha1.upper()}","{qfile_actual_sha1.upper()}","{qfile_actual_md5.upper()}","{qfile_actual_sha256.upper()}","{qds2}","{sid}","{sddls[:-102]}","{qds3}","{dd}","{guid}","{"Yes" if qdl == "ce20aaaa06000000" else "No"}","{"Yes" if header > 0 else "No"}","{attribType}","{attribData}","{extradata}",{logEntry}\n')
