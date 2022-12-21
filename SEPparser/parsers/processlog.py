import time
import helpers.utils as utils
import helpers.enums as enums


def parse_processlog(f, logEntries):
    processlog = ''
    startEntry = 72
    nextEntry = utils.read_unpack_hex(f, startEntry, 3)
    processtime = time.time()
    count = 0

    while True:
        if (time.time() - processtime) > 1:
            utils.progress(count, logEntries, status='Parsing log entries')

        field28 = ''
        field29 = ''
        extra = ''
        logEntry = utils.read_log_entry(f, startEntry, nextEntry).split(b'\t')
        dateAndTime = utils.from_win_64_hex(logEntry[1])
        eventID = enums.processlog_event_id.get(int(logEntry[2], 16) if logEntry[2] else '', logEntry[2])
        severity = int(logEntry[3], 16)
        action = enums.processlog_action.get(int(logEntry[4], 16) if logEntry[4] else '', logEntry[4])
        testmode = enums.test_mode.get(int(logEntry[5], 16) if logEntry[5] else '', logEntry[5])
        description = logEntry[6].decode("utf-8", "ignore")
        api = logEntry[7].decode("utf-8", "ignore")
        rulename = logEntry[11].decode("utf-8", "ignore")
        callerprocessid = int(logEntry[12], 16)
        callerprocess = logEntry[13].decode("utf-8", "ignore")
        target = logEntry[16].decode("utf-8", "ignore")
        location = logEntry[17].decode("utf-8", "ignore")
        user = logEntry[18].decode("utf-8", "ignore")
        userdomain = logEntry[19].decode("utf-8", "ignore")
        ipaddress = utils.from_hex_ip(logEntry[22])
        deviceinstanceid = logEntry[23].decode("utf-8", "ignore")
        filesize = int(logEntry[24], 16)
        ipv6 = utils.from_hex_ipv6(logEntry[26].split(b'\r\n')[0])

        try:
            extra = logEntry[26].split(b'\r\n')[1]

        except:
            field28 = logEntry[27].decode("utf-8", "ignore")
            field29 = logEntry[28].split(b'\r\n')[0].decode("utf-8", "ignore")
            extra = logEntry[28].split(b'\r\n')[1]

        processlog += (f'"{f.name}","{int(logEntry[0].decode("utf-8", "ignore"), 16)}","{dateAndTime}","{severity}","{action}","{testmode}","{description}","{api}","{rulename}","{ipaddress}","{ipv6}","{callerprocessid}","{callerprocess}","{deviceinstanceid}","{target}","{filesize}","{user}","{userdomain}","{location}","{eventID}","{logEntry[8].decode("utf-8", "ignore")}","{utils.from_win_64_hex(logEntry[9])}","{utils.from_win_64_hex(logEntry[10])}","{logEntry[14].decode("utf-8", "ignore")}","{logEntry[15].decode("utf-8", "ignore")}","{logEntry[20].decode("utf-8", "ignore")}","{logEntry[21].decode("utf-8", "ignore")}","{logEntry[25].decode("utf-8", "ignore")}","{field28}","{field29}","{extra}"\n')
        count += 1

        if count == logEntries:
            break

        startEntry = startEntry + nextEntry
        f.seek(startEntry)
        check = f.read(1)

        if len(check) == 0:
            print(f'\033[1;31mEntry mismatch: {count} entries found. Should be {logEntries}.\033[1;0m\n')
            break

        nextEntry = utils.read_unpack_hex(f, startEntry, 3)

    return processlog
