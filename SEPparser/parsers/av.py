import parsers.logline as logline
import parsers.tamper as tamperlog


def parse_daily_av(f, logType, tz):
    timeline = ''
    tamperProtect = ''
    if logType == 6:
        f.seek(0)
        logEntry = f.readline()

    if logType == 7:
        f.seek(388, 0)
        logEntry = f.read(2048).split(b'\x00\x00')[0]

    if logType == 8:
        f.seek(4100, 0)
        logEntry = f.read(1112).split(b'\x00\x00')[0]

    while logEntry:
        logEntry = logline.read_log_data(logEntry, tz)

        if logEntry.split('","')[1] == 'SECURITY_SYMPROTECT_POLICYVIOLATION':
            tamperProtect += tamperlog.parse_tamper_protect(logEntry.split('","'), logEntry, f.name)

        timeline += (f'"{f.name}","","","","","",{logEntry}\n')

        if logType == 7 or logType == 8:
            break

        logEntry = f.readline()

    return timeline, tamperProtect
