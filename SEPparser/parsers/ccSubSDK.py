import os
import parsers.ASN1 as ASN1
import parsers.reports as reports
import helpers.utils as utils


def extract_sym_ccSubSDK(f, hex_dump, extract_blob, output):
    guid = {
            '2B5CA624B61E3F408B994BF679001DC2': 'BHSvcPlg',
            '334FC1F5F2DA574E9BE8A16049417506': 'SubmissionsEim',  # CLSID_SAVAVSAMPLESUBMISSION
            '38ACED4CA8B2134D83ED4D35F94338BD': 'SubmissionsEim',  # CLSID_SAVAVPINGSUBMISSION
            '5E6E81A4A77338449805BB2B7AB12FB4': 'AtpiEim_ReportSubmission',  # OID_REPORTSUBMISSION
            '6AB68FC93C09E744B828A598179EFC83': 'IDSxpx86',
            '95AAE6FD76558D439889B9D02BE0B850': 'IDSxpx86',
            '6A007A980A5B0A48BDFC4D887AEACAB0': 'IDSxpx86',
            'D40650BD02FDE745889CB15F0693C770': 'IDSxpx86',
            '3DC1B6DEBAE889458213D8B252C465FC': 'IDSxpx86',
            '8EF95B94E971E842BAC952B02E79FB74': 'AVModule',
            'A72BBCC1E52A39418B8BB591BDD9AE76': 'RepMgtTim',  # OID_CATSUBMISSION
            'F2ECB3F7D763AE4DB49322CF763FC270': 'ccSubEng'
           }

    f.seek(0)
    GUID = f.read(16).hex()
    dll = None

    for k, v in guid.items():
        if k == GUID.upper():
            dll = v
            GUID = v + '/' + GUID

    key = f.read(16)
    data = f.read()
    dec = utils.blowfishit(data, key)

    if not hex_dump:
        if not os.path.exists(output + '/ccSubSDK/' + GUID + '/' + os.path.basename(f.name)):
            os.makedirs(output + '/ccSubSDK/' + GUID + '/' + os.path.basename(f.name))

        newfilename = open(output + '/ccSubSDK/' + GUID + '/' + os.path.basename(f.name) + '/Symantec_ccSubSDK.out', 'wb')
        newfilename.write(dec.encode('latin-1'))
        newfilename.close()
    dec = ASN1.read_sep_tag(dec.encode('latin-1'),
                            os.path.basename(f.name),
                            dll=dll,
                            hex_dump=hex_dump,
                            output=output)

    if not hex_dump:
        reports.write_report(dec[0], os.path.basename(f.name), output)
        newfilename = open(output + '/ccSubSDK/' + GUID + '/' + os.path.basename(f.name) + '/Symantec_ccSubSDK.met', 'wb')
        newfilename.write(dec[6].encode('latin-1'))
        newfilename.close()

        if dec[9] and extract_blob:
            cnt = 0

            for i in dec[9]:
                binary = open(output + '/ccSubSDK/' + GUID + '/' + os.path.basename(f.name) + '/' + str(cnt) + '.blob', 'wb')
                binary.write(i)
                binary.close()
                cnt += 1
