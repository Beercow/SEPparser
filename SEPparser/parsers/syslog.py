import time
import helpers.utils as utils
import helpers.enums as enums
import parsers.logline as logline


def parse_syslog(f, logEntries):
    syslog = ''
    timeline = ''
    startEntry = 72
    nextEntry = utils.read_unpack_hex(f, startEntry, 8)
    systime = time.time()
    count = 0

    while True:
        if (time.time() - systime) > 1:
            utils.progress(count, logEntries, status='Parsing log entries')

        data = '""'
        size = ''
        logEntry = utils.read_log_entry(f, startEntry, nextEntry).split(b'\t')
        dateAndTime = utils.from_win_64_hex(logEntry[1])
        event_id = enums.syslog_event_id.get(logEntry[2].decode("utf-8", "ignore").upper(), logEntry[2].decode("utf-8", "ignore").upper())
        severity = enums.syslog_severity.get(int(logEntry[4], 16) if logEntry[4] else '', logEntry[4])
        eds = int(logEntry[5].decode("utf-8", "ignore"), 16)
        summary = logEntry[6].decode("utf-8", "ignore").replace('"', '""')
        type = logEntry[7].decode("utf-8", "ignore")

        if eds == 11:
            size = int(logEntry[8][2:10], 16)

        if eds > 11:
            data = logline.read_log_data(logEntry[8], 0)

        try:
            location = logEntry[9].decode("utf-8", "ignore")
        except:
            location = ''

        syslog += (f'"{f.name}","{int(logEntry[0].decode("utf-8", "ignore"), 16)}","{dateAndTime}","{event_id}","{logEntry[3].decode("utf-8", "ignore")}","{severity}","{summary}","{eds}","{type}","{size}","{location}",{data}\n')

        if len(data) > 2:
            timeline += (f'"{f.name}","","","","","",{data}\n')

        count += 1

        if count == logEntries:
            break

        startEntry, moreData = utils.entry_check(f, startEntry, nextEntry)

        if moreData is False:
            print(f'\033[1;31mEntry mismatch: {count} entries found. Should be {logEntries}.\033[1;0m\n')
            break

        nextEntry = utils.read_unpack_hex(f, startEntry, 8)

    return syslog, timeline
