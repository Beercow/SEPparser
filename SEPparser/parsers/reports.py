import os
import re
import io
import zlib
import json
import xml.etree.ElementTree as ET
import helpers.utils as utils
import helpers.enums as enums

__vis_filter = b'................................ !"#$%&\'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[.]^_`abcdefghijklmnopqrstuvwxyz{|}~.................................................................................................................................'


def read_ndca(_):
    _ = io.BytesIO(_)
    _.seek(20)
    bodylength = int(utils.flip(_.read(4).hex()), 16)
    _.seek(4, 1)
    total = int(utils.flip(_.read(4).hex()), 16)
    _.seek(9, 1)
    n = 0
    msg = []

    while n != total:
        header = int(_.read(7)[3:-3].hex(), 16)
        datalength = int(utils.flip(_.read(2).hex()), 16)
        entrylength = int(utils.flip(_.read(2).hex()), 16)
        entry = _.read(entrylength).decode("utf-8", "ignore")

        if header == 6:
            data = _.read(datalength).decode("utf-8", "ignore")

        else:
            data = int(utils.flip(_.read(datalength).hex()), 16)

        msg.append(f'{entry}  {data}')
        _.seek(1, 1)
        n += 1

    _.seek(-1, 1)
    msg.append(_.read(bodylength).decode("utf-8", "ignore").translate(__vis_filter))

    return '\n'.join(msg)


def read_submission(_, fname, index, output, filenames):
    test = {}
    column = 0
    _ = _.split('","')
    description = _[3]
    report = _[4]
    component = _[5]
    md5 = _[6]
    sha256 = _[7]

    for x in report.split('\r\n'):
        x = re.split('(?<!.{48}):(?!\\\)|(?<!.{48})=', x, maxsplit=1)

        if x[0] == 'Detection Digest':
            y = x
            column = 2

        if column == 2:
            if len(x[0]) == 0:
                x = y
                x[1] = x[1].replace('"', '""')
                column = 0

            if len(x) == 1:
                y[1] = y[1] + x[0] + '\n'
                continue

        if len(x[0]) == 0:
            continue

        if len(x) == 1:
            if re.match('[a-fA-F\d]{32}', x[0]):
                x.insert(0, 'MD5')

            elif re.match('Detection of', x[0]):
                x.insert(0, 'Detection')

            elif re.search('Submission of', x[0]):
                x.insert(0, 'Submission')

            elif re.match('BASH-', x[0]):
                x.insert(0, 'BASH Plugin')
                column = 1

            elif 'BASH-' in description:
                x.insert(0, 'ImagePath')
                column = 0

            else:
                x.insert(0, 'Unknown')

        test[x[0]] = x[1]

    if 'Submission' in test:
        subtype = output+'/ccSubSDK/SubmissionsEim.csv'

    elif 'BASH-' in description:
        subtype = output+'/ccSubSDK/BHSvcPlg.csv'

    elif ('Signature Set Version' in test or 'Signature ID' in test):
        subtype = output+'/ccSubSDK/IDSxp.csv'

    elif description == 'File Reputation':
        subtype = output+'/ccSubSDK/AtpiEim_ReportSubmission.csv'

    elif description == 'Client Authentication Token Request':
        subtype = output+'/ccSubSDK/RepMgtTim.csv'

    elif component == 'DU':
        subtype = output+'/ccSubSDK/ccSubEng.csv'

    else:
        subtype = output+'/ccSubSDK/Reports.csv'

    header = []
    data = ['']

    if os.path.isfile(subtype):
        data = open(subtype).readlines()
        header = data[0][1:-2].split('","')
        header.remove('Index')
        header.remove('ccSubSDK File GUID')
        header.remove('Present')
        if 'BASH-' in description:
            header.remove('SONAR')
            header.remove('BASH Plugin')
            header.remove('MD5')
            header.remove('SHA256')
        if 'Detection of' in description:
            header.remove('Detection')
            header.remove('MD5')
            header.remove('SHA256')

    subtype = open(subtype, 'w', errors="ignore", encoding='utf-8')
    rows = ''
    value = []

    for k, v in test.items():
        if k not in header:
            header.append(k)

        if len(header) > len(value):
            diff = len(header) - len(value)
            value += ' ' * diff

        pos = header.index(k)

        if k == 'Network Data':
            value[pos] = read_ndca(zlib.decompress(bytearray.fromhex(v[17:]))).replace('"', '""')

        elif k == 'Attack Data':
            if os.path.basename(subtype.name) == 'IDSxp.csv':
                try:
                    attdata = zlib.decompress(bytearray.fromhex(v[17:])).decode("utf-8", "ignore")
                    parsed = json.dumps(json.loads(attdata), indent=4)
                    value[pos] = parsed.replace('"', '""')

                except:
                    value[pos] = utils.hexdump(zlib.decompress(bytearray.fromhex(v[17:]))).replace('"', '""')

            else:
                value[pos] = utils.hexdump(zlib.decompress(bytearray.fromhex(v[17:]))).replace('"', '""')

        elif k == 'Protocol':
            value[pos] = utils.mixed_dict(enums.idsxp_protocol, int(v))

        elif k == 'Application File CreateTime':
            value[pos] = utils.from_unix_sec(v.strip()[:10])

        else:
            value[pos] = v

    present = ''

    if any(fname in files for files in filenames):
        present = 'yes'
    else:
        present = 'no'

    value = '","'.join(value)
    if 'BASH-' in description or 'Detection of' in description:
        rows += f'"{index}","{fname}","{present}","{description}","{md5}","{sha256}","{value}",""\n'
    else:
        rows += f'"{index}","{fname}","{present}","{value}"\n'

    header = '","'.join(header)
    if 'BASH-' in description:
        data[0] = f'"Index","ccSubSDK File GUID","Present","BASH Plugin","MD5","SHA256","{header}","SONAR"\n'
    elif 'Detection of' in description:
        data[0] = f'"Index","ccSubSDK File GUID","Present","Detection","MD5","SHA256","{header}"\n'
    else:
        data[0] = f'"Index","ccSubSDK File GUID","Present","{header}"\n'
    subtype.writelines(data)
    subtype.write(rows)
    subtype.close()


def write_report(_, fname, output):
    for r in _:
        for m in re.finditer('(?P<XML><Report Type="(?P<Report>.*?)".*Report>)', r):
            reportname = output+'/ccSubSDK/'+m.group('Report')+'.csv'
            header = []
            data = ['']

            if os.path.isfile(reportname):
                data = open(reportname).readlines()
                header = data[0][1:-2].split('","')
                header.remove('File Name')

            reporttype = open(reportname, 'w', encoding='utf-8')
            tree = ET.fromstring(m.group('XML').translate(__vis_filter))
            rows = ''

            for node in tree.iter():
                value = []

                for k, v in node.attrib.items():
                    if k == 'Type' or k == 'Count':
                        continue

                    else:
                        if k not in header:
                            header.append(k)

                        if len(header) > len(value):
                            diff = len(header) - len(value)
                            value += ' ' * diff

                        pos = header.index(k)

                        if k == 'Infection_Timestamp' or k == 'Discovery_Timestamp' or k == 'Active_timestamp':
                            value[pos] = utils.from_unix_sec(v)

                        else:
                            value[pos] = v

                if len(value) != 0:
                    value = '","'.join(value)
                    rows += f'"{fname}","{value}"\n'

            header = '","'.join(header)
            data[0] = f'"File Name","{header}"\n'
            reporttype.writelines(data)
            reporttype.write(rows)
            reporttype.close()
