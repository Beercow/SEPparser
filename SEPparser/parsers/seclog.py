import re
import time
import base64
import json
import helpers.utils as utils
import helpers.enums as enums
import parsers.logline as logline


def parse_seclog(f, logEntries):
    seclog = ''
    timeline = ''
    startEntry = 72
    nextEntry = utils.read_unpack_hex(f, startEntry, 8)
    sectime = time.time()
    count = 0

    while True:
        if (time.time() - sectime) > 1:
            utils.progress(count, logEntries, status='Parsing log entries')

        logEntry = utils.read_log_entry(f, startEntry, nextEntry).split(b'\t', 16)
        logData = []
        data = ''

        if int(logEntry[12], 16) == 0:
            logData = ['']

        else:
            if re.match(b'^([A-Za-z0-9+/]{4})*([A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{2}==)?$', logEntry[16][:int(logEntry[12], 16)]):
                logData = ['']
                parsed = json.loads(base64.b64decode(logEntry[16][:int(logEntry[12], 16)]).decode("utf-8", "ignore"))
                data = json.dumps(parsed, indent=4, sort_keys=True)
                data = data.replace('"', '""')

            else:
                logData = logline.read_log_data(logEntry[16][:int(logEntry[12], 16)], 0).split(",")

        dateAndTime = utils.from_win_64_hex(logEntry[1])
        eventtype = enums.seclog_event_id.get(int(logEntry[2], 16) if logEntry[2] else '', logEntry[2])
        severity = utils.range_dict(enums.seclog_severity, logEntry[3])
        localhost = utils.from_hex_ip(logEntry[4])
        remotehost = utils.from_hex_ip(logEntry[5])
        protocol = enums.seclog_protocol.get(int(logEntry[6], 16) if logEntry[6] else '', logEntry[6])
        direction = enums.seclog_direction.get(int(logEntry[8], 16) if logEntry[8] else '', logEntry[8])
        begintime = utils.from_win_64_hex(logEntry[9])
        endtime = utils.from_win_64_hex(logEntry[10])
        occurrences = int(logEntry[11], 16)
        description = logEntry[13].decode("utf-8", "ignore")
        application = logEntry[15].decode("utf-8", "ignore")
        logEntry2 = logEntry[16][int(logEntry[12], 16):].split(b'\t')
        localmac = logEntry2[1].hex()

        if len(localmac) < 32:
            while True:
                logEntry2[1] = logEntry2[1] + b'\t'
                logEntry2[1:3] = [b''.join(logEntry2[1:3])]
                localmac = logEntry2[1].hex()

                if len(localmac) == 32:
                    localmac = utils.from_hex_mac(logEntry2[1].hex())
                    break

        else:
            localmac = utils.from_hex_mac(logEntry2[1].hex())

        remotemac = logEntry2[2].hex()

        if len(remotemac) < 32:
            while True:
                logEntry2[2] = logEntry2[2] + b'\t'
                logEntry2[2:4] = [b''.join(logEntry2[2:4])]
                remotemac = logEntry2[2].hex()

                if len(remotemac) == 32:
                    remotemac = utils.from_hex_mac(logEntry2[2].hex())
                    break

        else:
            remotemac = utils.from_hex_mac(logEntry2[2].hex())

        location = logEntry2[3].decode("utf-8", "ignore")
        user = logEntry2[4].decode("utf-8", "ignore")
        userdomain = logEntry2[5].decode("utf-8", "ignore")
        signatureid = int(logEntry2[6], 16)
        signaturesubid = int(logEntry2[7], 16)
        remoteport = int(logEntry2[10], 16)
        localport = int(logEntry2[11], 16)
        REMOTE_HOST_IPV6 = utils.from_hex_ipv6(logEntry2[12])
        LOCAL_HOST_IPV6 = utils.from_hex_ipv6(logEntry2[13])
        signaturename = logEntry2[14].decode("utf-8", "ignore")
        xintrusionpayloadurl = logEntry2[15].decode("utf-8", "ignore")
        intrusionurl = logEntry2[16].decode("utf-8", "ignore")

        try:
            urlcategories = ''
            urlhidlevel = ''
            urlriskscore = ''
            urlcategories = ''
            hash = logEntry2[22].decode("utf-8", "ignore").strip('\r')
            # SEP14.3.0.1
            urlhidlevel = logEntry2[23].decode("utf-8", "ignore")
            urlriskscore = logEntry2[24].decode("utf-8", "ignore")
            catlist = logEntry2[25].decode("utf-8", "ignore").split(",")
            for cat in catlist:
                urlcategories += enums.url_categories.get(int(cat.rstrip()), cat.rstrip()) + ','

        except:
            pass

        seclog += (f'"{f.name}","{int(logEntry[0].decode("utf-8", "ignore"), 16)}","{dateAndTime}","{eventtype}","{severity}","{direction}","{protocol}","{remotehost}","{remoteport}","{remotemac}","{localhost}","{localport}","{localmac}","{application}","{signatureid}","{signaturesubid}","{signaturename}","{intrusionurl}","{xintrusionpayloadurl}","{user}","{userdomain}","{location}","{occurrences}","{endtime}","{begintime}","{hash}","{description}","{logEntry[7].decode("utf-8", "ignore")}","{int(logEntry[12], 16)}","{logEntry[14].decode("utf-8", "ignore")}","{logEntry2[8].decode("utf-8", "ignore")}","{logEntry2[9].decode("utf-8", "ignore")}","{REMOTE_HOST_IPV6}","{LOCAL_HOST_IPV6}","{logEntry2[17].decode("utf-8", "ignore")}","{logEntry2[18].decode("utf-8", "ignore")}","{logEntry2[19].decode("utf-8", "ignore")}","{logEntry2[20].decode("utf-8", "ignore")}","{logEntry2[21].decode("utf-8", "ignore")}","{urlhidlevel}","{urlriskscore}","{urlcategories[:-1]}","{data}",{",".join(logData)}\n')

        if len(logData) > 1:
            timeline += (f'"{f.name}","{int(logEntry[12], 16)}","","","","",{",".join(logData)}\n')

        count += 1

        if count == logEntries:
            break

        startEntry, moreData = utils.entry_check(f, startEntry, nextEntry)

        if moreData is False:
            print(f'\033[1;31mEntry mismatch: {count} entries found. Should be {logEntries}.\033[1;0m\n')
            break

        nextEntry = utils.read_unpack_hex(f, startEntry, 8)

    return seclog, timeline
