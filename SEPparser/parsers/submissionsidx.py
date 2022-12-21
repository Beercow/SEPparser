import os
import struct
import io
import re
import time
import helpers.utils as utils
import parsers.ASN1 as ASN1
import parsers.reports as reports


def extract_sym_submissionsidx(f, submissions, index, hex_dump, output, filenames):
    fsize = f.seek(0, 2)
    f.seek(48)
    subtime = time.time()
    cnt = 0

    if index:
        if hex_dump:
            print(f'Searching {f.name} for submission {index}.\n')
        else:
            print("\033[1;31m-i, --index can only be used with -hd, --hex-dump.\033[1;0m\n")
            return None

    while f.read(4) == b'@\x99\xc6\x89':
        if (time.time() - subtime) > 1 and index:
            utils.progress(f.tell(), fsize, status='Parsing submissions.idx')
        unknown_1 = f.read(4)
        idx_pos = struct.unpack('q', f.read(8))[0]
        last_idx = struct.unpack('q', f.read(8))[0]
        len1 = struct.unpack('i', f.read(4))[0]
        len2 = struct.unpack('i', f.read(4))[0]
        unknown_2 = f.read(8).hex()
        key = f.read(16)
        data = f.read(len1 - 16)
        dec = utils.blowfishit(data, key)
        if not index:
            print(f'\033[1;35m\tSubmission {cnt} len1={len1} len2={len2}\033[1;0m\n')

        if not hex_dump:
            if not os.path.exists(output + '/ccSubSDK/submissions'):
                os.makedirs(output + '/ccSubSDK/submissions')

            newfilename = open(output + '/ccSubSDK/submissions/submissions.idx_Symantec_submission_['+str(cnt)+']_idx.out', 'wb')
            newfilename.write(dec.encode('latin-1'))

        if hex_dump:
            if index:
                if index == str(cnt):
                    if (time.time() - subtime) > 1:
                        print('')
                    dec = ASN1.read_sep_tag(dec.encode('latin-1'), f.name, sub=True, hex_dump=hex_dump)
                    if dec[6] == '':
                        print(f'\n\033[1;31mSubmission {index} contains sub-entries. Unable to dump hex.\033[1;0m\n')
                    return None
                else:
                    dec = ASN1.read_sep_tag(dec.encode('latin-1'), f.name, sub=True)
            else:
                dec = ASN1.read_sep_tag(dec.encode('latin-1'), f.name, sub=True, hex_dump=hex_dump)
        else:
            dec = ASN1.read_sep_tag(dec.encode('latin-1'), f.name, sub=True, hex_dump=hex_dump)
        if dec[6] == '':
            if not hex_dump:
                newfilename.close()
                os.remove(newfilename.name)
                submissions.write(f'"{cnt}-0","{unknown_1}","{idx_pos}","{last_idx}","{len1}","{len2}","{unknown_2}","{dec[7]}",{dec[8]}\n')
            f.seek(-len1 - 40, 1)
            data = f.read(len1 + 40)
            imatch = extract_sym_submissionsidx_sub(data, cnt, len1, subtime, submissions, index, hex_dump, output, filenames)
            if imatch:
                return None
            cnt += 1
            continue

        if not hex_dump:
            newfilename = open(output + '/ccSubSDK/submissions/submissions.idx_Symantec_submission_['+str(cnt)+']_idx.met', 'wb')

            newfilename.write(dec[6].encode('latin-1'))
            submissions.write(f'"{cnt}","{unknown_1}","{idx_pos}","{last_idx}","{len1}","{len2}","{unknown_2}","{dec[7]}",{dec[8]}\n')
            if dec[7]:
                reports.read_submission(dec[8], dec[7], cnt, output, filenames)

        if not index:
            print(f'\033[1;32m\tFinished parsing Submission {cnt}\033[1;0m\n')

        cnt += 1
    if index:
        return True


def extract_sym_submissionsidx_sub(f, cnt, len1, subtime, submissions, index, hex_dump, output, filenames):
    if not index:
        print(f'\033[1;32m\t\tParsing sub-entries for Submission {cnt}\033[1;0m\n')

    subcnt = 0

    if index == f'{cnt}-{subcnt}':
        print(f'\n\n\033[1;31mSubmission {index} contains sub-entries. Unable to dump hex.\033[1;0m\n')
        return True

    if not hex_dump:
        newfilename = open(output + '/ccSubSDK/submissions/submissions.idx_Symantec_submission_['+str(cnt)+'-'+str(subcnt)+']_idx.out', 'wb')

    f = io.BytesIO(f)

    try:
        pos = [(m.start(0)) for m in re.finditer(b'@\x99\xc6\x89', f.read())][1]
        if not index:
            print(f'\033[1;35m\t\tSubmission {cnt}-{subcnt} len1={pos} len2=0\033[1;0m\n')

    except:
        f.seek(0)
        if not index:
            print(f'\033[1;35m\t\tSubmission {cnt}-{subcnt} len1={len1} len2=0 exception\033[1;0m\n')
        if not hex_dump:
            newfilename.write(f.read())
        if not index:
            print(f'\033[1;32m\t\tFinished parsing Submission {cnt}-0 exception\033[1;0m\n')
        return

    f.seek(0)
    if not hex_dump:
        newfilename.write(f.read(pos))
    else:
        f.read(pos)
    if not index:
        print(f'\033[1;32m\t\tFinished parsing Submission {cnt}-0\033[1;0m\n')
    subcnt += 1

    while f.read(4) == b'@\x99\xc6\x89':
        unknown_1 = f.read(4)
        idx_pos = struct.unpack('q', f.read(8))[0]
        last_idx = struct.unpack('q', f.read(8))[0]
        len1 = struct.unpack('i', f.read(4))[0]
        len2 = struct.unpack('i', f.read(4))[0]
        unknown_2 = f.read(8).hex()
        key = f.read(16)
        data = f.read(len1 - 16)
        dec = utils.blowfishit(data, key)
        if not index:
            print(f'\033[1;35m\t\tSubmission {cnt}-{subcnt} len1={len1} len2={len2}\033[1;0m\n')

        if not hex_dump:
            newfilename = open(output + '/ccSubSDK/submissions/submissions.idx_Symantec_submission_['+str(cnt)+'-'+str(subcnt)+']_idx.out', 'wb')
            newfilename.write(dec.encode('latin-1'))

        if hex_dump:
            if index:
                if index == f'{cnt}-{subcnt}':
                    if (time.time() - subtime) > 1:
                        print('')
                    dec = ASN1.read_sep_tag(dec.encode('latin-1'), None, sub=True, hex_dump=hex_dump)
                    return True
                else:
                    dec = ASN1.read_sep_tag(dec.encode('latin-1'), None, sub=True)
            else:
                dec = ASN1.read_sep_tag(dec.encode('latin-1'), None, sub=True, hex_dump=hex_dump)
        else:
            dec = ASN1.read_sep_tag(dec.encode('latin-1'), None, sub=True, hex_dump=hex_dump)

        if not hex_dump:
            newfilename = open(output + '/ccSubSDK/submissions/submissions.idx_Symantec_submission_['+str(cnt)+'-'+str(subcnt)+']_idx.met', 'wb')
            newfilename.write(dec[6].encode('latin-1'))
            submissions.write(f'"{cnt}-{subcnt}","{unknown_1}","{idx_pos}","{last_idx}","{len1}","{len2}","{unknown_2}","{dec[7]}",{dec[8]}\n')
            if dec[7]:
                reports.read_submission(dec[8], dec[7], str(cnt)+'-'+str(subcnt), output, filenames)

        if not index:
            print(f'\033[1;32m\t\tFinished parsing Submission {cnt}-{subcnt}\033[1;0m\n')
        subcnt += 1
