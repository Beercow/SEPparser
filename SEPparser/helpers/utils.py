import sys
import time
from datetime import datetime, timedelta
import ipaddress
import io
import blowfish


def read_unpack_hex(f, loc, count):
    # jump to the specified location
    f.seek(loc)

    raw = f.read(count)
    result = int(raw, 16)

    return result


def hexdump(buf, packet=False, pcap=False, hex_dump=False):  # not touching yet
    """Return a hexdump output string of the given buffer."""
    total = len(buf)
    file = io.BytesIO(buf)
    res = []
    hextime = time.time()

    for length in range(0, len(buf), 16):
        i = file.tell()

        if (time.time() - hextime) > 1 and not hex_dump:
            progress(i, total, status='Dumping Hex')

        data = file.read(16)
        hexa = ' '.join(['{:02x}'.format(i) for i in data])
        line = ''.join([31 < i < 127 and chr(i) or '.' for i in data])
        res.append('  {:08x}  {:47}  {}'.format(length, hexa, line))

    if (time.time() - hextime) > 1 and not hex_dump:
        print('\n')

    if pcap:
        packet.write('\n'.join(res))
        packet.write('\n\n')

        return '\n'.join(res)

    else:
        return '\n'.join(res)+'\n\n'


def read_log_entry(f, loc, count):

    # jump to the specified location
    f.seek(loc)

    return f.read(count)


def from_unix_sec(_):
    try:
        return datetime.utcfromtimestamp(int(_)).strftime('%Y-%m-%d %H:%M:%S')

    except:
        return datetime.utcfromtimestamp(0).strftime('%Y-%m-%d %H:%M:%S')


def from_win_64_hex(dateAndTime):
    """Convert a Windows 64 Hex Big-Endian value to a date"""
    base10_microseconds = int(dateAndTime, 16) / 10

    try:
        dateAndTime = datetime(1601, 1, 1) + timedelta(microseconds=base10_microseconds)

    except:
        dateAndTime = datetime(1601, 1, 1)

    return dateAndTime.strftime('%Y-%m-%d %H:%M:%S.%f')


def from_symantec_time(timestamp, tz):
    year, month, day_of_month, hours, minutes, seconds = (
        int(hexdigit[0] + hexdigit[1], 16) for hexdigit in zip(
            timestamp[::2], timestamp[1::2]))

    timestamp = datetime(year + 1970, month + 1,
                         day_of_month,
                         hours,
                         minutes,
                         seconds) + timedelta(hours=tz)

    return timestamp.strftime('%Y-%m-%d %H:%M:%S')


def from_hex_ip(ipHex):
    ipHex = ipHex.decode("utf-8", "ignore")

    if ipHex == '0':
        return '0.0.0.0'

    if len(ipHex) != 8:
        ipHex = '0' + ipHex

    try:
        ipv4 = (
            int(hexdigit[0] + hexdigit[1], 16) for hexdigit in zip(
                ipHex[::2], ipHex[1::2]))

        return '.'.join(map(str, reversed(list(ipv4))))

    except:
        return '0.0.0.0'


def from_hex_ipv6(ipHex):
    ipHex = ipHex.decode("utf-8", "ignore")
    chunks = [ipHex[i:i+2] for i in range(0, len(ipHex), 2)]

    try:
        ipv6 = (
            x[0] + x[1] for x in zip(
                chunks[1::2], chunks[::2]))

        return ipaddress.ip_address(':'.join(ipv6)).compressed

    except:
        return '::'


def from_hex_mac(macHex):
    mac = (
        hexdigit[0] + hexdigit[1] for hexdigit in zip(
            macHex[::2], macHex[1::2]))

    return '-'.join(map(str, mac))[0:17]


def flip(_):
    _ = (hexdigit[0] + hexdigit[1] for hexdigit in zip(
        _[::2], _[1::2]))
    _ = ''.join(map(str, reversed(list(_))))

    return _


def entry_check(f, startEntry, nextEntry):
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
        return startEntry, False

    return startEntry, True


def progress(count, total, status=''):
    bar_len = 60
    filled_len = int(round(bar_len * count / float(total)))

    percents = round(100.0 * count / float(total), 1)
    bar = '=' * filled_len + '-' * (bar_len - filled_len)

    sys.stderr.write(f'[{bar}] {percents}% ...{status}\r')
    sys.stderr.flush()


def range_dict(rdict, v):
    v = int(v, 16) if v else ''

    for k in rdict:
        if v in k:
            return rdict[k]
    else:
        return v


def mixed_dict(mdict, _):
    for k, v in mdict.items():
        if isinstance(k, int):
            if k == _:
                return v
        else:
            if _ in k:
                return mdict[k]

    return _


def blowfishit(data, key):
    dec = ''
    total = len(data)
    cipher = blowfish.Cipher(key, byte_order="little")
    data = io.BytesIO(data)

    while data:
        dec += str(cipher.decrypt_block(data.read(8)).decode('latin-1'))
        i = data.tell()

        if total > 1000000:
            progress(i, total, status='Decrypting file')

        check = data.read(1)

        if len(check) == 0:
            break

        data.seek(-1, 1)

    if total > 1000000:
        print('\n')

    return dec


banner = r'''
\033[1;93m____________\033[1;0m
\033[1;93m|   |  |   |\033[1;0m
\033[1;93m|   |  |   |\033[1;97m   ____  _____ ____
\033[1;93m|   |  |   |\033[1;97m  / ___|| ____|  _ \ _ __   __ _ _ __ ___  ___ _ __
\033[1;93m|   |  |\033[1;92m___\033[1;93m|\033[1;97m  \___ \|  _| | |_) | '_ \ / _` | '__/ __|/ _ \ '__|
\033[1;93m \  |  \033[1;92m/ _ \ \033[1;97m  ___) | |___|  __/| |_) | (_| | |  \__ \  __/ |
\033[1;93m  \ | \033[1;92m| (_) |\033[1;97m |____/|_____|_|   | .__/ \__,_|_|  |___/\___|_| v{}
\033[1;93m    \  \033[1;92m\___/\033[1;97m                    |_|
\033[1;93m     \/\033[1;0m      by @bmmaloney97
'''
