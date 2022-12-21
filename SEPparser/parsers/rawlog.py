import time
from scapy.all import Ether
from scapy.utils import import_hexcap
import helpers.utils as utils
import helpers.enums as enums


def parse_raw(f, logEntries, rawlog, packet, hex_dump):
    startEntry = 72
    nextEntry = utils.read_unpack_hex(f, startEntry, 8)
    rawtime = time.time()
    count = 0

    while True:
        if (time.time() - rawtime) > 1:
            utils.progress(count, logEntries, status='Parsing log entries')

        logEntry = utils.read_log_entry(f, startEntry, nextEntry).split(b'\t')

        if len(logEntry) > 20:
            while True:
                logEntry[13] = logEntry[13] + b'\t'
                logEntry[13:15] = [b''.join(logEntry[13:15])]

                if len(logEntry) == 20:
                    break

        dateAndTime = utils.from_win_64_hex(logEntry[1])
        eventId = enums.raw_event_id.get(int(logEntry[2], 16) if logEntry[2] else '', logEntry[2])
        localhost = utils.from_hex_ip(logEntry[3])
        remotehost = utils.from_hex_ip(logEntry[4])
        localport = int(logEntry[5], 16)
        remoteport = int(logEntry[6], 16)
        plength = int(logEntry[7], 16)
        direction = enums.raw_direction.get(int(logEntry[8], 16) if logEntry[8] else '', logEntry[8])
        action = enums.raw_action.get(int(logEntry[9], 16) if logEntry[9] else '', logEntry[9])
        application = logEntry[12].decode("utf-8", "ignore")
        packetdecode = utils.hexdump(logEntry[13],  packet=packet, pcap=True, hex_dump=hex_dump).replace('"', '""')
        rule = logEntry[14].decode("utf-8", "ignore")
        packetdump = Ether(import_hexcap(utils.hexdump(logEntry[13], packet=packet, pcap=True, hex_dump=hex_dump))).show(dump=True)

        rawlog.write(f'"{f.name}","{int(logEntry[0].decode("utf-8", "ignore"), 16)}","{dateAndTime}","{remotehost}","{remoteport}","{localhost}","{localport}","{direction}","{action}","{application}","{rule}","{packetdump}","{packetdecode}","{eventId}","{plength}","{logEntry[10].decode("utf-8", "ignore")}","{logEntry[11].decode("utf-8", "ignore")}","{logEntry[15].decode("utf-8", "ignore")}","{logEntry[16].decode("utf-8", "ignore")}","{logEntry[17].decode("utf-8", "ignore")}","{logEntry[18].decode("utf-8", "ignore")}","{logEntry[19].decode("utf-8", "ignore")}"\n')
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
