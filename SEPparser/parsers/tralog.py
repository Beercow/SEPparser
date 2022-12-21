import time
import helpers.utils as utils
import helpers.enums as enums


def mixed_dict(mdict, _):
    for k, v in mdict.items():
        if isinstance(k, int):
            if k == _:
                return v
        else:
            if _ in k:
                return mdict[k]

    return _


def nested_dict(ndict, lp, rp):
    codeDescription = ''
    for k, v in ndict.items():
        if isinstance(k, int):
            if k == lp:
                typeName = ndict[lp]['type']
                code = ndict[lp]
                break
        else:
            if lp in k:
                typeName = ndict[k]['type']
                code = ndict[k]
                break

    for k, v in code.items():
        if isinstance(k, str):
            continue
        if isinstance(k, int):
            if k == rp:
                codeDescription = ndict[lp][rp]
        else:
            if rp in k:
                codeDescription = ndict[lp][k]

    return typeName, codeDescription


def parse_tralog(f, logEntries):
    tralog = ''
    startEntry = 72
    nextEntry = utils.read_unpack_hex(f, startEntry, 8)
    tratime = time.time()
    count = 0

    while True:
        if (time.time() - tratime) > 1:
            utils.progress(count, logEntries, status='Parsing log entries')

        logEntry = utils.read_log_entry(f, startEntry, nextEntry).split(b'\t')
        dateAndTime = utils.from_win_64_hex(logEntry[1])
        protocol = enums.tralog_protocol.get(int(logEntry[2], 16) if logEntry[2] else '', int(logEntry[2], 16))
        localhost = utils.from_hex_ip(logEntry[3])
        remotehost = utils.from_hex_ip(logEntry[4])
        localport = int(logEntry[5], 16)
        remoteport = int(logEntry[6], 16)

        if protocol == "ICMPv4 packet":
            typeName, codeDescription = nested_dict(enums.icmp_type_code, localport, remoteport)
            protocol = f'{protocol} [type={localport}, code={remoteport}]\r\nName:{typeName}\r\nDescription:{codeDescription}'
            localport = ''
            remoteport = ''

        if protocol == "Ethernet packet":
            protocol = f'{protocol} [type={hex(localport)}]\r\nDescription: {mixed_dict(enums.eth_type, localport)}'
            localport = ''
            remoteport = ''
        direction = enums.tralog_direction.get(int(logEntry[7], 16) if logEntry[7] else '', logEntry[7])
        endtime = utils.from_win_64_hex(logEntry[8])
        begintime = utils.from_win_64_hex(logEntry[9])
        occurrences = int(logEntry[10], 16)
        action = enums.tralog_action.get(int(logEntry[11], 16) if logEntry[11] else '', logEntry[11])
        severity = utils.range_dict(enums.tralog_severity, logEntry[13])
        rule = logEntry[16].decode("utf-8", "ignore")
        application = logEntry[17].decode("utf-8", "ignore")
        localmac = logEntry[18].hex()

        if len(localmac) < 32:
            while True:
                logEntry[18] = logEntry[18] + b'\t'
                logEntry[18:20] = [b''.join(logEntry[18:20])]
                localmac = logEntry[18].hex()

                if len(localmac) == 32:
                    localmac = utils.from_hex_mac(logEntry[18].hex())
                    break

        else:
            localmac = utils.from_hex_mac(logEntry[18].hex())

        remotemac = logEntry[19].hex()

        if len(remotemac) < 32:
            while True:
                logEntry[19] = logEntry[19] + b'\t'
                logEntry[19:21] = [b''.join(logEntry[19:21])]
                remotemac = logEntry[19].hex()

                if len(remotemac) == 32:
                    remotemac = utils.from_hex_mac(logEntry[19].hex())
                    break

        else:
            remotemac = utils.from_hex_mac(logEntry[19].hex())

        location = logEntry[20].decode("utf-8", "ignore")
        user = logEntry[21].decode("utf-8", "ignore")
        userdomain = logEntry[22].decode("utf-8", "ignore")

        try:
            field33 = logEntry[32].decode("utf-8", "ignore")
            field34 = logEntry[33].decode("utf-8", "ignore")

        except:
            field33 = ''
            field34 = ''

        tralog += (f'"{f.name}","{int(logEntry[0].decode("utf-8", "ignore"), 16)}","{dateAndTime}","{action}","{severity}","{direction}","{protocol}","{remotehost}","{remotemac}","{remoteport}","{localhost}","{localmac}","{localport}","{application}","{user}","{userdomain}","{location}","{occurrences}","{begintime}","{endtime}","{rule}","{logEntry[12].decode("utf-8", "ignore")}","{logEntry[14].decode("utf-8", "ignore")}","{logEntry[15].decode("utf-8", "ignore")}","{logEntry[23].decode("utf-8", "ignore")}","{logEntry[24].decode("utf-8", "ignore")}","{utils.from_hex_ipv6(logEntry[25])}","{utils.from_hex_ipv6(logEntry[26])}","{logEntry[27].decode("utf-8", "ignore")}","{logEntry[28].decode("utf-8", "ignore")}","{logEntry[29].decode("utf-8", "ignore")}","{logEntry[30].decode("utf-8", "ignore")}","{logEntry[31].decode("utf-8", "ignore")}","{field33}","{field34}"\n')
        count += 1

        if count == logEntries:
            break

        startEntry = startEntry + nextEntry
        f.seek(startEntry)
        check = f.read(1)

        while check != b'0':
            startEntry += 1
            f.seek(startEntry)
            check = f.read(1)

            if len(check) == 0:
                break

            if check == b'0':
                f.seek(startEntry)

        if len(check) == 0:
            print(f'\033[1;31mEntry mismatch: {count} entries found. Should be {logEntries}.\033[1;0m\n')
            break

        nextEntry = utils.read_unpack_hex(f, startEntry, 8)

    return tralog

