import re
import base64
import json
import helpers.enums as enums
import helpers.utils as utils


class LogFields:
    api = ''
    dateAndTime = ''
    severity = ''
    direction = ''
    summary = ''
    type = ''
    size = ''
    time = ''
    event = ''
    category = ''
    logger = ''
    computer = ''
    user = ''
    virus = ''
    file = ''
    wantedaction1 = ''
    wantedaction2 = ''
    realaction = ''
    virustype = ''
    flags = ''
    description = ''
    scanid = ''
    newext = ''
    groupid = ''
    eventdata = ''
    vbinid = ''
    virusid = ''
    quarantineforwardstatus = ''
    access = ''
    sdnstatus = ''
    compressed = ''
    depth = ''
    stillinfected = ''
    definfo = ''
    defsequincenumber = ''
    cleaninfo = ''
    deleteinfo = ''
    backupod = ''
    parent = ''
    guid = ''
    clientgroup = ''
    address = ''
    domainname = ''
    ntdomain = ''
    macaddress = ''
    version = ''
    remotemachine = ''
    remotemachineip = ''
    action1status = ''
    action2status = ''
    licensefeaturename = ''
    licensefeatureversion = ''
    licenseserialnumber = ''
    licensefulfillmentid = ''
    licensestartdate = ''
    licenseexpirationdate = ''
    licenselifecycle = ''
    licenseseatstotal = ''
    licenseseats = ''
    errorcode = ''
    licenseseatsdelta = ''
    status = ''
    domainguid = ''
    sessionguid = ''
    vbnsessionid = ''
    logindomain = ''
    eventdata2 = ''
    erasercategoryid = ''
    dynamiccategoryset = ''
    subcategorysetid = ''
    displaynametouse = ''
    reputationdisposition = ''
    reputationconfidence = ''
    firsseen = ''
    reputationprevalence = ''
    downloadurl = ''
    categoryfordropper = ''
    cidsstate = ''
    behaviorrisklevel = ''
    detectiontype = ''
    acknowledgetext = ''
    vsicstate = ''
    scanguid = ''
    scanduration = ''
    scanstarttime = ''
    targetapptype = ''
    scancommandguid = ''
    rulename = ''
    callerprocessid = ''
    callerprocess = ''
    deviceinstanceid = ''
    target = ''
    userdomain = ''
    location = ''
    ipaddress = ''
    testmode = ''
    filesize = ''
    eventtype = ''
    signatureid = ''
    signaturesubid = ''
    signaturename = ''
    intrusionurl = ''
    xintrusionpayloadurl = ''
    hash = ''
    actor = ''
    targetprocess = ''
    packetdump = ''
    packetdecode = ''
    digitalsigner = ''
    digitalissuer = ''
    digitalthumbprint = ''
    digitalsn = ''
    digitaltime = ''
    action = ''
    objecttype = ''
    location = ''
    urlhidlevel = ''
    urlriskscore = ''
    urlcategories = ''


def log_flags(_):

    flagStr = ''
    if _ & 0x400000:
        flagStr = flagStr + "EB_ACCESS_DENIED "

    if _ & 0x800000:
        flagStr = flagStr + "EB_NO_VDIALOG "

    if _ & 0x1000000:
        flagStr = flagStr + "EB_LOG "

    if _ & 0x2000000:
        flagStr = flagStr + "EB_REAL_CLIENT "

    if _ & 0x4000000:
        flagStr = flagStr + "EB_ENDUSER_BLOCKED "

    if _ & 0x8000000:
        flagStr = flagStr + "EB_AP_FILE_WIPED "

    if _ & 0x10000000:
        flagStr = flagStr + "EB_PROCESS_KILLED "

    if _ & 0x20000000:
        flagStr = flagStr + "EB_FROM_CLIENT "

    if _ & 0x40000000:
        flagStr = flagStr + "EB_EXTRN_EVENT "

    if _ & 0x1FF:

        if _ & 0x1:
            flagStr = flagStr + "FA_SCANNING_MEMORY "

        if _ & 0x2:
            flagStr = flagStr + "FA_SCANNING_BOOT_SECTOR "

        if _ & 0x4:
            flagStr = flagStr + "FA_SCANNING_FILE "

        if _ & 0x8:
            flagStr = flagStr + "FA_SCANNING_BEHAVIOR "

        if _ & 0x10:
            flagStr = flagStr + "FA_SCANNING_CHECKSUM "

        if _ & 0x20:
            flagStr = flagStr + "FA_WALKSCAN "

        if _ & 0x40:
            flagStr = flagStr + "FA_RTSSCAN "

        if _ & 0x80:
            flagStr = flagStr + "FA_CHECK_SCAN "

        if _ & 0x100:
            flagStr = flagStr + "FA_CLEAN_SCAN "

    if _ & 0x803FFE00:
        flagStr = flagStr + "EB_N_OVERLAYS("

        if _ & 0x200:
            flagStr = flagStr + "N_OFFLINE "

        if _ & 0x400:
            flagStr = flagStr + "N_INFECTED "

        if _ & 0x800:
            flagStr = flagStr + "N_REPSEED_SCAN "

        if _ & 0x1000:
            flagStr = flagStr + "N_RTSNODE "

        if _ & 0x2000:
            flagStr = flagStr + "N_MAILNODE "

        if _ & 0x4000:
            flagStr = flagStr + "N_FILENODE "

        if _ & 0x8000:
            flagStr = flagStr + "N_COMPRESSED "

        if _ & 0x10000:
            flagStr = flagStr + "N_PASSTHROUGH "

        if _ & 0x40000:
            flagStr = flagStr + "N_DIRNODE "

        if _ & 0x80000:
            flagStr = flagStr + "N_ENDNODE "

        if _ & 0x100000:
            flagStr = flagStr + "N_MEMNODE "

        if _ & 0x200000:
            flagStr = flagStr + "N_ADMIN_REQUEST_REMEDIATION "

        flagStr = flagStr[:-1] + ")"

    return flagStr


def log_description(data):
    try:
        if data[3] == '2' and data[64] == '1':
            return 'AP realtime defferd scanning'

    except:
        pass

    return data[13].strip('"')


def event_data1(_):
    pos = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]
    _ = _.replace('"', '').split('\t')

    if len(_) < 13:
        diff = 13 - len(_)
        b = [''] * diff
        _.extend(b)

    if ':' in _[0]:
        var = _[0]
        _ = _[0].split(':')
        _.insert(0, var)
        b = [''] * 7
        _.extend(b)

    labels = event_data1_labels(_[0])

    if _[0] == '101':
        _[9] = enums.remediation_type_desc.get(int(_[9]) if _[9] else '', _[9])

    assert(len(labels) == len(pos))
    acc = 0

    for i in range(len(labels)):
        _.insert(pos[i]+acc, labels[i])
        acc += 1

    _ = '","'.join(_)

    return _


def event_data1_labels(_):
    labels = []

    if _ == '101':
        labels = ["GUID", "Unknown", "Num Side Effects Repaired", "Anonaly Action Type", "Anomaly Action Operation", "Unknown", "Anomaly Name", "Anomaly Categories", "Anomaly Action Type ID", "Anomaly Action OperationID", "Previous Log GUID", "Unknown"]

    elif _ == '201':
        labels = ["Unknown", "Unknown", "Unknown", "Unknown", "Unknown", "Unknown", "Unknown", "Unknown", "Unknown", "Unknown", "Unknown", "Unknown"]

    elif _ == '301':
        labels = ["Actor PID", "Actor", "Event", "Target PID", "Target", "Target Process", "Unknown", "Unknown", "N/A", "N/A", "N/A", "N/A"]

    elif len(_) > 3:
        labels = ["Scan Status", "Risks", "Scanned", "Files/Folders/Drives Omitted", "Trusted Files Skipped", "N/A", "N/A", "N/A", "N/A", "N/A", "N/A", "N/A"]

    else:
        labels = [''] * 12

    return labels


def event_data2(_):
    _ = _.replace('"', '').split('\t')
    if len(_) < 17:
        diff = 17 - len(_)
        b = [''] * diff
        _.extend(b)

    _[3] = enums.hash_type.get(int(_[3]) if _[3] else '', _[3])
    _ = '","'.join(_)

    return _


def read_log_data(data, tz):
    entry = LogFields()
    data = re.split(',(?=(?:[^\"]*\"[^\"]*\")*[^\"]*$)',
                    data.decode("utf-8", "ignore"))
    field113 = ''
    field115 = ''
    field119 = ''
    field122 = ''
    field123 = ''
    field124 = ''
    field125 = ''
    field126 = ''
    entry.time = utils.from_symantec_time(data[0], tz)
    entry.event = enums.event.get(int(data[1])if data[1] else '', data[1])
    entry.category = enums.category.get(int(data[2])if data[2] else '', data[2])
    entry.logger = enums.logger.get(int(data[3])if data[3] else '', data[3])
    entry.computer = data[4]
    entry.user = data[5]
    entry.virus = data[6]
    entry.file = data[7]
    entry.wantedaction1 = enums.ll_action.get(int(data[8])if data[8] else '', data[8])
    entry.wantedaction2 = enums.ll_action.get(int(data[9])if data[9] else '', data[9])
    entry.realaction = enums.ll_action.get(int(data[10])if data[10] else '', data[10])
    entry.virustype = enums.virus_type.get(int(data[11])if data[11] else '', data[11])
    entry.flags = log_flags(int(data[12]))
    entry.description = log_description(data)
    entry.scanid = data[14]
    entry.newext = data[15]
    entry.groupid = data[16]
    entry.eventdata = event_data1(data[17])
    entry.vbinid = data[18]
    entry.virusid = data[19]
    entry.quarantineforwardstatus = enums.quarantine_forward_status.get(int(data[20])if data[20] else '', data[20])
    entry.access = data[21]
    entry.sdnstatus = data[22]
    entry.compressed = enums.yn.get(int(data[23])if data[23] else '', data[23])
    entry.depth = data[24]
    entry.stillinfected = enums.yn.get(int(data[25]) if data[25] else '', data[25])
    entry.definfo = data[26]
    entry.defsequincenumber = data[27]
    entry.cleaninfo = enums.clean_info.get(int(data[28])if data[28] else '', data[28])
    entry.deleteinfo = enums.delete_info.get(int(data[29]) if data[29] else '', data[29])
    entry.backupod = data[30]
    entry.parent = data[31]
    entry.guid = data[32]
    entry.clientgroup = data[33]
    entry.address = data[34]
    entry.domainname = data[35]
    entry.ntdomain = data[36]
    entry.macaddress = data[37]
    entry.version = data[38]
    entry.remotemachine = data[39]
    entry.remotemachineip = data[40]
    entry.action1status = data[41]
    entry.action2status = data[42]
    entry.licensefeaturename = data[43]
    entry.licensefeatureversion = data[44]
    entry.licenseserialnumber = data[45]
    entry.licensefulfillmentid = data[46]
    entry.licensestartdate = data[47]
    entry.licenseexpirationdate = data[48]
    entry.licenselifecycle = data[49]
    entry.licenseseatstotal = data[50]
    entry.licenseseats = data[51]
    entry.errorcode = data[52]
    entry.licenseseatsdelta = data[53]
    entry.status = enums.eraser_status.get(int(data[54])if data[54] else '', data[54])
    entry.domainguid = data[55]
    entry.sessionguid = data[56]
    entry.vbnsessionid = data[57]
    entry.logindomain = data[58]

    try:
        entry.eventdata2 = event_data2(data[59])
        entry.erasercategoryid = enums.eraser_category_id.get(int(data[60]) if data[60] else '', data[60])  # out of range
        entry.dynamiccategoryset = enums.dynamic_categoryset_id.get(int(data[61]) if data[61] else '', data[61])
        entry.subcategorysetid = data[62]  # out of range
        entry.displaynametouse = enums.display_name.get(int(data[63])if data[63] else '', data[63])
        entry.reputationdisposition = enums.reputation_disposition.get(int(data[64])if data[64] else '', data[64])
        entry.reputationconfidence = utils.range_dict(enums.reputation_confidence, data[65])
        entry.firsseen = data[66]
        entry.reputationprevalence = utils.range_dict(enums.reputation_prevalence, data[67])
        entry.downloadurl = data[68]
        entry.categoryfordropper = data[69]
        entry.cidsstate = enums.cids_state.get(int(data[70])if data[70] else '', data[70])
        entry.behaviorrisklevel = data[71]
        entry.detectiontype = enums.detection_type.get(int(data[72])if data[72] else '', data[72])
        entry.acknowledgetext = data[73]
        entry.vsicstate = enums.vsic_state.get(int(data[74]) if data[74] else '', data[74])
        entry.scanguid = data[75]
        entry.scanduration = data[76]
        entry.scanstarttime = utils.from_symantec_time(data[77], tz)
        entry.targetapptype = enums.targetapp_type.get(int(data[78])if data[78] else '', data[78])
        entry.scancommandguid = data[79]

    except IndexError:
        pass

    try:
        field113 = data[80]
        entry.location = data[81]  # out of range
        field115 = data[82]  # out of range
        entry.digitalsigner = data[83].replace('"', '')  # out of range
        entry.digitalissuer = data[84]
        entry.digitalthumbprint = data[85]
        field119 = data[86]
        entry.digitalsn = data[87]
        entry.digitaltime = utils.from_unix_sec(data[88])
        field122 = data[89]  # out of range
        field123 = data[90]  # out of range
        if re.match('^(?:[a-zA-Z0-9+/]{4})*(?:|(?:[a-zA-Z0-9+/]{3}=)|(?:[a-zA-Z0-9+/]{2}==)|(?:[a-zA-Z0-9+/]{1}===))$', data[91]):  # out of range
            try:
                parsed = json.loads(base64.b64decode(data[91]))
                field124 = json.dumps(parsed, indent=4, sort_keys=True)
                field124 = field124.replace('"', '""')

            except:
                field124 = data[91]

        else:
            field124 = data[91]

        field125 = data[92]  # out of range
        field126 = data[93]  # out of range

    except IndexError:
        pass

    return f'"{entry.time}","{entry.event}","{entry.category}","{entry.logger}","{entry.computer}","{entry.user}","{entry.virus}","{entry.file}","{entry.wantedaction1}","{entry.wantedaction2}","{entry.realaction}","{entry.virustype}","{entry.flags}","{entry.description}","{entry.scanid}","{entry.newext}","{entry.groupid}","{entry.eventdata}","{entry.vbinid}","{entry.virusid}","{entry.quarantineforwardstatus}","{entry.access}","{entry.sdnstatus}","{entry.compressed}","{entry.depth}","{entry.stillinfected}","{entry.definfo}","{entry.defsequincenumber}","{entry.cleaninfo}","{entry.deleteinfo}","{entry.backupod}","{entry.parent}","{entry.guid}","{entry.clientgroup}","{entry.address}","{entry.domainname}","{entry.ntdomain}","{entry.macaddress}","{entry.version}","{entry.remotemachine}","{entry.remotemachineip}","{entry.action1status}","{entry.action2status}","{entry.licensefeaturename}","{entry.licensefeatureversion}","{entry.licenseserialnumber}","{entry.licensefulfillmentid}","{entry.licensestartdate}","{entry.licenseexpirationdate}","{entry.licenselifecycle}","{entry.licenseseatstotal}","{entry.licenseseats}","{entry.errorcode}","{entry.licenseseatsdelta}","{entry.status}","{entry.domainguid}","{entry.sessionguid}","{entry.vbnsessionid}","{entry.logindomain}","{entry.eventdata2}","{entry.erasercategoryid}","{entry.dynamiccategoryset}","{entry.subcategorysetid}","{entry.displaynametouse}","{entry.reputationdisposition}","{entry.reputationconfidence}","{entry.firsseen}","{entry.reputationprevalence}","{entry.downloadurl}","{entry.categoryfordropper}","{entry.cidsstate}","{entry.behaviorrisklevel}","{entry.detectiontype}","{entry.acknowledgetext}","{entry.vsicstate}","{entry.scanguid}","{entry.scanduration}","{entry.scanstarttime}","{entry.targetapptype}","{entry.scancommandguid}","{field113}","{entry.location}","{field115}","{entry.digitalsigner}","{entry.digitalissuer}","{entry.digitalthumbprint}","{field119}","{entry.digitalsn}","{entry.digitaltime}","{field122}","{field123}","{field124}","{field125}","{field126}"'
