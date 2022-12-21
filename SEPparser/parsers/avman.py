import time
import helpers.utils as utils
import parsers.logline as logline
import parsers.tamper as tamperlog


def parse_avman(f, logEntries):
    timeline = ''
    tamperProtect = ''
    startEntry = 55
    nextEntry = utils.read_unpack_hex(f, startEntry, 8)
    avtime = time.time()
    count = 0

    while True:
        if (time.time() - avtime) > 1:
            utils.progress(count, logEntries, status='Parsing log entries')

        logEntry = utils.read_log_entry(f,
                                        startEntry,
                                        nextEntry).split(b'\t', 5)

        logData = logline.read_log_data(logEntry[5], 0)

        if logData.split('","')[1] == 'SECURITY_SYMPROTECT_POLICYVIOLATION':
            tamperProtect += tamperlog.parse_tamper_protect(logData.split('","'),
                                                            logEntry,
                                                            f.name)

        timeline += (f'"{f.name}","{int(logEntry[0].decode("utf-8", "ignore"), 16)}","{utils.from_win_64_hex(logEntry[1])}","{utils.from_win_64_hex(logEntry[2])}","{utils.from_win_64_hex(logEntry[3])}","{logEntry[4].decode("utf-8", "ignore")}",{logData}\n')

        count += 1

        if count == logEntries:
            break

        startEntry, moreData = utils.entry_check(f, startEntry, nextEntry)

        if moreData is False:
            print(f'\033[1;31mEntry mismatch: {count} entries found. Should be {logEntries}.\033[1;0m\n')
            break

        nextEntry = utils.read_unpack_hex(f, startEntry, 8)

    return timeline, tamperProtect
