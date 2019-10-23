import os
import sys
import re
import time
import argparse
import binascii
from datetime import datetime,timedelta

def csv_header():

    syslog.write('"File Name","Record Length","Date And Time","Field3","Field4","Severity","summary","Field6","Type","Size_(bytes)","LOG:Time(UTC)","LOG:Event","LOG:Category","LOG:Logger","LOG:Computer","LOG:User","LOG:Virus","LOG:File","LOG:WantedAction1","LOG:WantedAction2","LOG:RealAction","LOG:Virus_Type","LOG:Flags","LOG:Description","LOG:ScanID","LOG:New_Ext","LOG:Group_ID","LOG:Event_Data","LOG:VBin_ID","LOG:Virus_ID","LOG:Quarantine_Forward_Status","LOG:Access","LOG:SDN_Status","LOG:Compressed","LOG:Depth","LOG:Still_Infected","LOG:Def_Info","LOG:Def_Sequence_Number","LOG:Clean_Info","LOG:Delete_Info","LOG:Backup_ID","LOG:Parent","LOG:GUID","LOG:Client_Group","LOG:Address","LOG:Domain_Name","LOG:NT_Domain","LOG:MAC_Address","LOG:Version","LOG:Remote_Machine","LOG:Remote_Machine_IP","LOG:Action_1_Status","LOG:Action_2_Status","LOG:License_Feature_Name","LOG:License_Feature_Version","LOG:License_Serial_Number","LOG:License_Fulfillment_ID","LOG:License_Start_Date","LOG:License_Expiration_Date","LOG:License_LifeCycle","LOG:License_Seats_Total","LOG:License_Seats","LOG:Error_Code","LOG:License_Seats_Delta","LOG:Status","LOG:Domain_GUID","LOG:Session_GUID","LOG:VBin_Session_ID","LOG:Login_Domain","LOG:Event_Data_2","LOG:Eraser_Category_ID","LOG:Dynamic_Categoryset_ID","LOG:Subcategoryset_ID","LOG:Display_Name_To_Use","LOG:Reputation_Disposition","LOG:Reputation_Confidence","LOG:First_Seen","LOG:Reputation_Prevalence","LOG:Downloaded_URL","LOG:Creator_For_Dropper","LOG:CIDS_State","LOG:Behavior_Risk_Level","LOG:Detection_Type","LOG:Acknowledge_Text","LOG:VSIC_State","LOG:Scan_GUID","LOG:Scan_Duration","LOG:Scan_Start_Time","LOG:TargetApp","LOG:Scan_Command_GUID"\n')

    seclog.write('"File Name","Record Length","DateAndTime","Event Type","Severity","Direction","Protocol","Remote Host","Remote Port","Remote MAC","Local Host","Local Port","Local MAC","Application","Signature ID","Signature SubID","Signature Name","Intrusion-URL","X-Intrusion-Payload-URL","User","User Domain","Location","Occurrences","Begin Time","End Time","Hash","Description","Field7","Field8","Field13","Field15","Field17","Field25","Field26","Field29","Field30","Field34","LOG:Version","Profile_Serial_Number","Field37","Field38"\n')

    tralog.write('"File Name","Record Length","Date and Time","Action","Severity","Direction","Protocol","Remote Host","Remote MAC","Remote Port","Local Host","Local MAC","Local Port","Application","User","User Domain","Location","Occurrences","Begin Time","End Time","Rule","Field13","Field15","Field16","Field24","Field25","Field26","Field27","Field28","Field29","Field30","Field31","Field32"\n')

    rawlog.write('"File Name","Recode Length","Date and Time","Remote Host","Remote Port","Local Host","Local Port","Direction","Action","Application","Rule","Packet Dump","Packet Decode","Field3","Field8","Field9","Field10","Field11","Field12","Field16","Field17","Field18","Field19","Field20"\n')

    processlog.write('"File Name","Record Length","Date And Time","Severity","Action","Test Mode","Description","API","Rule Name","IP Address","Caller Process ID","Caller Process","Device Instance ID","Target","File Size","User","User Domain","Location","Field3","Field9","Field10","Field11","Field15","Field16","Field21","Field22","Field25","Field26","Field27"\n')

    timeline.write('"File Name","Record Length","Date/Time1","Date/Time2","Date/Time3","Field5","LOG:Time(UTC)","LOG:Event","LOG:Category","LOG:Logger","LOG:Computer","LOG:User","LOG:Virus","LOG:File","LOG:WantedAction1","LOG:WantedAction2","LOG:RealAction","LOG:Virus_Type","LOG:Flags","LOG:Description","LOG:ScanID","LOG:New_Ext","LOG:Group_ID","LOG:Event_Data1","LOG:Event_Data2 (301_Actor PID)","LOG:Event_Data3 (301_Actor)","LOG:Event_Data4 (301_Event)","LOG:Event_Data5 (301_Target PID)","LOG:Event_Data6 (301_Target)","LOG:Event_Data7 (301_Target Process)","LOG:Event_Data8","LOG:Event_Data9","LOG:Event_Data10","LOG:Event_Data11","LOG:Event_Data12","LOG:Event_Data13","LOG:VBin_ID","LOG:Virus_ID","LOG:Quarantine_Forward_Status","LOG:Access","LOG:SDN_Status","LOG:Compressed","LOG:Depth","LOG:Still_Infected","LOG:Def_Info","LOG:Def_Sequence_Number","LOG:Clean_Info","LOG:Delete_Info","LOG:Backup_ID","LOG:Parent","LOG:GUID","LOG:Client_Group","LOG:Address","LOG:Domain_Name","LOG:NT_Domain","LOG:MAC_Address","LOG:Version","LOG:Remote_Machine","LOG:Remote_Machine_IP","LOG:Action_1_Status","LOG:Action_2_Status","LOG:License_Feature_Name","LOG:License_Feature_Version","LOG:License_Serial_Number","LOG:License_Fulfillment_ID","LOG:License_Start_Date","LOG:License_Expiration_Date","LOG:License_LifeCycle","LOG:License_Seats_Total","LOG:License_Seats","LOG:Error_Code","LOG:License_Seats_Delta","LOG:Status","LOG:Domain_GUID","LOG:Session_GUID","LOG:VBin_Session_ID","LOG:Login_Domain","LOG:Event_Data_2_1","LOG:Event_Data_2_Company_Name","LOG:Event_Data_2_Size (bytes)","LOG:Event_Data_2_Hash_Type","LOG:Event_Data_2_Hash","LOG:Event_Data_2_Product_Version","LOG:Event_Data_2_7","LOG:Event_Data_2_8","LOG:Event_Data_2_9","LOG:Event_Data_2_10","LOG:Event_Data_2_11","LOG:Event_Data_2_12","LOG:Event_Data_2_Product_Name","LOG:Event_Data_2_14","LOG:Event_Data_2_15","LOG:Eraser_Category_ID","LOG:Dynamic_Categoryset_ID","LOG:Subcategoryset_ID","LOG:Display_Name_To_Use","LOG:Reputation_Disposition","LOG:Reputation_Confidence","LOG:First_Seen","LOG:Reputation_Prevalence","LOG:Downloaded_URL","LOG:Creator_For_Dropper","LOG:CIDS_State","LOG:Behavior_Risk_Level","LOG:Detection_Type","LOG:Acknowledge_Text","LOG:VSIC_State","LOG:Scan_GUID","LOG:Scan_Duration","LOG:Scan_Start_Time","LOG:TargetApp","LOG:Scan_Command_GUID","Field113","Field114","Filed115","Digital_Signatures_Signer","Digital_Signatures_Issuer","Digital_Signatures_Certificate_Thumbprint","Field119","Digital_Signatures_Serial_Number","Digital_Signatures_Signing_Time","Field122","Field123"\n')
    
    tamperProtect.write('"File Name","Computer","User","Action Taken","Object Type","Event","Actor","Target","Target Process","Date and Time"\n')

__vis_filter = b'................................ !"#$%&\'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[.]^_`abcdefghijklmnopqrstuvwxyz{|}~.................................................................................................................................'

class LogFields:
    api = ''
    dateAndTime =''
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
    virustype= ''
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

def sec_event_type(_):
    event_value = {
                   '209':'Host Integrity Failed',
                   '206':'Intrusion Prevention System',
                   '210':'Host Integrity Passed'
                   }
                   
    for k, v in event_value.items():
        if k == str(_):
            return v

    else:
        return _


def sec_network_protocol(_): 
    network_protocol = {
                        '1':'OTHERS',
                        '2':'TCP',
                        '3':'UDP',
                        '4':'ICMP'
                        }
                        
    for k, v in network_protocol.items():
        if k == str(_):
            return v

    else:
        return _

def log_severity(_):
    severity_value = {
                      '0':'Information',
                      '15':'Information',
                      '1':'Warning',
                      '2':'Error',
                      '3':'Critical',
                      '7':'Major'
                     }

    for k, v in severity_value.items():
        if k == str(_):
            return v

    else:
        return _

def log_direction(_):
    direction = {
                 '0':'Unknown',
                 '1':'Incoming',
                 '2':'Outgoing'
                }

    for k, v in direction.items():
        if k == str(_):
            return v

    else:
        return _

def log_description(data):
    if data[3].decode("utf-8", "ignore") is '2' and data[64].decode("utf-8", "ignore") is '1':
        return 'AP realtime defferd scanning'

    return data[13].decode("utf-8", "ignore").strip('"')

def log_event(_):
    event = {
              '1':'IS_ALERT',
              '2':'SCAN_STOP',
              '3':'SCAN_START',
              '4':'PATTERN_UPDATE',
              '5':'INFECTION',
              '6':'FILE_NOTOPEN',
              '7':'LOAD_PATTERN',
              '8':'MESSAGE_INFO',
              '9':'MESSAGE_ERROR',
              '10':'CHECKSUM',
              '11':'TRAP',
              '12':'CONFIG_CHANGE',
              '13':'SHUTDOWN',
              '14':'STARTUP',
              '16':'PATTERN_DOWNLOAD',
              '17':'TOO_MANY_VIRUSES',
              '18':'FWD_TO_QSERVER',
              '19':'SCANDLVR',
              '20':'BACKUP',
              '21':'SCAN_ABORT',
              '22':'RTS_LOAD_ERROR',
              '23':'RTS_LOAD',
              '24':'RTS_UNLOAD',
              '25':'REMOVE_CLIENT',
              '26':'SCAN_DELAYED',
              '27':'SCAN_RESTART',
              '28':'ADD_SAVROAMCLIENT_TOSERVER',
              '29':'REMOVE_SAVROAMCLIENT_FROMSERVER',
              '30':'LICENSE_WARNING',
              '31':'LICENSE_ERROR',
              '32':'LICENSE_GRACE',
              '33':'UNAUTHORIZED_COMM',
              '34':'LOG:FWD_THRD_ERR',
              '35':'LICENSE_INSTALLED',
              '36':'LICENSE_ALLOCATED',
              '37':'LICENSE_OK',
              '38':'LICENSE_DEALLOCATED',
              '39':'BAD_DEFS_ROLLBACK',
              '40':'BAD_DEFS_UNPROTECTED',
              '41':'SAV_PROVIDER_PARSING_ERROR',
              '42':'RTS_ERROR',
              '43':'COMPLIANCE_FAIL',
              '44':'COMPLIANCE_SUCCESS',
              '45':'SECURITY_SYMPROTECT_POLICYVIOLATION',
              '46':'ANOMALY_START',
              '47':'DETECTION_ACTION_TAKEN',
              '48':'REMEDIATION_ACTION_PENDING',
              '49':'REMEDIATION_ACTION_FAILED',
              '50':'REMEDIATION_ACTION_SUCCESSFUL',
              '51':'ANOMALY_FINISH',
              '52':'COMMS_LOGIN_FAILED',
              '53':'COMMS_LOGIN_SUCCESS',
              '54':'COMMS_UNAUTHORIZED_COMM',
              '55':'CLIENT_INSTALL_AV',
              '56':'CLIENT_INSTALL_FW',
              '57':'CLIENT_UNINSTALL',
              '58':'CLIENT_UNINSTALL_ROLLBACK',
              '59':'COMMS_SERVER_GROUP_ROOT_CERT_ISSUE',
              '60':'COMMS_SERVER_CERT_ISSUE',
              '61':'COMMS_TRUSTED_ROOT_CHANGE',
              '62':'OMMS_SERVER_CERT_STARTUP_FAILED',
              '63':'CLIENT_CHECKIN',
              '64':'CLIENT_NO_CHECKIN',
              '65':'SCAN_SUSPENDED',
              '66':'SCAN_RESUMED',
              '67':'SCAN_DURATION_INSUFFICIENT',
              '68':'CLIENT_MOVE',
              '69':'SCAN_FAILED_ENHANCED',
              '70':'COMPLIANCE_FAILEDAUDIT',
              '71':'HEUR_THREAT_NOW_WHITELISTED',
              '72':'INTERESTING_PROCESS_DETECTED_START',
              '73':'LOAD_ERROR_BASH',
              '74':'LOAD_ERROR_BASH_DEFINITIONS',
              '75':'INTERESTING_PROCESS_DETECTED_FINISH',
              '76':'BASH_NOT_SUPPORTED_FOR_OS',
              '77':'HEUR_THREAT_NOW_KNOWN',
              '78':'DISABLE_BASH',
              '79':'ENABLE_BASH',
              '80':'DEFS_LOAD_FAILED',
              '81':'LOCALREP_CACHE_SERVER_ERROR',
              '82':'REPUTATION_CHECK_TIMEOUT',
              '83':'SYMEPSECFILTER_DRIVER_ERROR',
              '84':'VSIC_COMMUNICATION_WARNING',
              '85':'VSIC_COMMUNICATION_RESTORED',
              '86':'ELAM_LOAD_FAILED',
              '87':'ELAM_INVALID_OS',
              '88':'ELAM_ENABLE',
              '89':'ELAM_DISABLE',
              '90':'ELAM_BAD',
              '91':'ELAM_BAD_REPORTED_AS_UNKNOWN',
              '92':'DISABLE_SYMPROTECT',
              '93':'ENABLE_SYMPROTECT',
              '94':'NETSEC_EOC_PARSE_FAILED'
            }

    for k, v in event.items():
        if k == _:
            return v

    else:
        return _

def log_category(_):
    category = {
                  '1':'Infection',
                  '2':'Summary',
                  '3':'Pattern',
                  '4':'Security'
                }

    for k, v in category.items():
        if k == _:
            return v

    else:
        return _

def log_logger(_):
    logger = {
                '0':'Scheduled',
                '1':'Manual',
                '2':'Real_Time',
                '3':'Integrity_Shield',
                '6':'Console',
                '7':'VPDOWN',
                '8':'System',
                '9':'Startup',
                '10':'Idle',
                '11':'DefWatch',
                '12':'Licensing',
                '13':'Manual_Quarantine',
                '14':'SymProtect',
                '15':'Reboot_Processing',
                '16':'Bash',
                '17':'SymElam',
                '18':'PowerEraser',
                '19':'EOCScan',
                '100':'LOCAL_END',
                '101':'Client',
                '102':'Forewarded',
                '256':'Transport_Client'
             }

    for k, v in logger.items():
        if k == _:
            return v

    else:
        return _

def log_action(_):
    action = {
                '4294967295#':'Invalid',
                '1':'Quarantine',
                '2':'Rename',
                '3':'Delete',
                '4':'Leave Alone',
                '5':'Clean',
                '6':'Remove Macros',
                '7':'Save file as...',
                '8':'Send to backend',
                '9':'Restore from Quarantine',
                '10':'Rename Back (unused)',
                '11':'Undo Action',
                '12':'Error',
                '13':'Backup to quarantine (backup view)',
                '14':'Pending Analysis',
                '16':'Terminate Process Required',
                '17':'Exclude from Scanning',
                '18':'Reboot Processing',
                '19':'Clean by Deletion',
                '20':'Access Denied',
                '21':'TERMINATE PROCESS ONLY',
                '22':'NO REPAIR',
                '23':'FAIL',
                '24':'RUN POWERTOOL',
                '25':'NO REPAIR POWERTOOL',
                '110':'INTERESTING PROCESS CAL',
                '111':'INTERESTING PROCESS DETECTED',
                '1000':'INTERESTING PROCESS HASHED DETECTED',
                '1001':'DNS HOST FILE EXCEPTOION'
              }

    for k, v in action.items():
        if k == _:
            return v

    else:
        return _


def log_c_action(_):
    action = {
              '0':'Allow',
              '1':'Block',
              '2':'Ask',
              '3':'Continue',
              '4':'Terminate'
              }

    for k, v in action.items():
        if k == str(_):
            return v

    else:
        return _

def log_virus_type(_):
    virus = {
             '48':'Heuristic',
             '64':'Reputation',
             '80':'Hack Tools',
             '96':'Spyware',
             '112':'Trackware',
             '128':'Dialers',
             '144':'Remote Access',
             '160':'Adware',
             '176':'Joke Programs',
             '224':'Heuristic Application',
             }

    for k, v in virus.items():
        if k == _:
            return v
    
    else:
        return _

def log_eraser_category_id(_):
    eraser = {
              '1':'HeuristicTrojanWorm',
              '2':'HeuristicKeyLogger',
              '100':'CommercialRemoteControl',
              '101':'CommercialKeyLogger',
              '200':'Cookie',
              '300':'Shields'
              }

    for k, v in eraser.items():
        if k == _:
            return v

    else:
        return _

def log_dynamic_categoryset_id(_):
    id = {
          '1':'MALWARE',
          '2':'SECURITY_RISK',
          '3':'POTENTIALLY_UNWANTED_APPLICATIONS',
          '4':'EXPERIMENTAL_HEURISTIC',
          '5':'LEGACY_VIRAL',
          '6':'LEGACY_NON_VIRAL',
          '7':'VATEGORY_CRIMEWARE',
          '8':'ADVANCED_HEURISTICS',
          '9':'REPUTATION_BACKED_ADVANCED_HEURISTICS',
          '10':'PREVALENCE_BACKED_ADVANCED_HEURISTICS'
          }

    for k, v in id.items():
        if k == _:
            return v

    else:
        return _

def log_reputation_disposition(_):
    rep = {
           '0':'Good',
           '1':'Bad',
           '127':'Unknown'
          }

    for k, v in rep.items():
        if k == _:
            return v

    else:
        return _

def log_detection_type(_):
    dtype = {
            '0':'Traditional',
            '1':'Heuristic'
            }

    for k, v in dtype.items():
        if k == _:
            return v

    else:
        return _

def log_vsic_state(_):
    state = {
             '0':'Off',
             '1':'On',
             '':'Failed'
            }

    for k, v in state.items():
        if k == _:
            return v

    else:
        return _

def log_target_app_type(_):
    target = {
              '0':'Normal',
              '1':'Metro'
             }

    for k, v in target.items():
        if k == _:
            return v

    else:
        return _

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

def remediation_type_desc(_):
#LOG:Event_Data10
    remType = {
               '2000':'Registry',
               '2001':'File',
               '2002':'Process',
               '2003':'Batch File',
               '2004':'INI File',
               '2005':'Service',
               '2006':'Infected File',
               '2007':'COM Object',
               '2008':'Host File Entry',
               '2009':'Directory',
               '2010':'Layered Service Provider',
               '2011':'Internet Browser Cache'
               }

def hash_type(_):

    hashType = {
                '0':'MD5',
                '1':'SHA-1',
                '2':'SHA-256'
                }

    for k, v in hashType.items():
        if k == _:
            return v
            
    return _

def log_tp_event(eventType, _):

    if eventType == '301':
        event = {
                 '1':'Create',
                 '55':'Open',
                 '56':'Duplicate'
                }

        for k, v in event.items():
            if k == _:
                return v
    
    return _

def log_tp_object_type(_):

    objectType = {
                 '0':'File'
                 }

    for k, v in objectType.items():
        if k == str(len(_)):
            return v
     
    return 'Process'

def protocol(_):
    protocol = {
                '301':'TCP',
                '302':'UDP',
                '303':'Ping',
                '304':'TCP',
                '305':'Other',
                '306':'ICMP',
                '307':'Ethernet',
                '308':'IP'
                }
                
    for k, v in protocol.items():
        if k == str(_):
            return v

    else:
        return _

def test_mode(_):
    testMode = {
                '0':'Production',
                '1':'Yes'
                }
             
    for k, v in testMode.items():
        if k == str(_):
            return v
            
    return _

def read_unpack_hex(f, loc, count):
    
    # jump to the specified location
    f.seek(loc)

    raw = f.read(count)
    result = int(raw, 16)

    return result

def read_log_entry(f, loc, count):
    
    # jump to the specified location
    f.seek(loc)
    
    return f.read(count)

def read_log_data(data):
    entry = LogFields()
    data = data.split(b',')
    entry.time = from_symantec_time(data[0].decode("utf-8", "ignore"))
    entry.event = log_event(data[1].decode("utf-8", "ignore"))
    entry.category = log_category(data[2].decode("utf-8", "ignore"))
    entry.logger = log_logger(data[3].decode("utf-8", "ignore"))
    entry.computer = data[4].decode("utf-8", "ignore")
    entry.user = data[5].decode("utf-8", "ignore")
    entry.virus = data[6].decode("utf-8", "ignore")
    entry.file = data[7].decode("utf-8", "ignore")
    entry.wantedaction1 = log_action(data[8].decode("utf-8", "ignore"))
    entry.wantedaction2 = log_action(data[9].decode("utf-8", "ignore"))
    entry.realaction = log_action(data[10].decode("utf-8", "ignore"))
    entry.virustype= log_virus_type(data[11].decode("utf-8", "ignore"))
    entry.flags = log_flags(int(data[12].decode("utf-8", "ignore")))
    entry.description = log_description(data)
    entry.scanid = data[14].decode("utf-8", "ignore")
    entry.newext = data[15].decode("utf-8", "ignore")
    entry.groupid = data[16].decode("utf-8", "ignore")
    entry.eventdata = data[17].decode("utf-8", "ignore")
    entry.vbinid = data[18].decode("utf-8", "ignore")
    entry.virusid = data[19].decode("utf-8", "ignore")
    entry.quarantineforwardstatus = data[20].decode("utf-8", "ignore")
    entry.access = data[21].decode("utf-8", "ignore")
    entry.sdnstatus = data[22].decode("utf-8", "ignore")
    entry.compressed = data[23].decode("utf-8", "ignore")
    entry.depth = data[24].decode("utf-8", "ignore")
    entry.stillinfected = data[25].decode("utf-8", "ignore")
    entry.definfo = data[26].decode("utf-8", "ignore")
    entry.defsequincenumber = data[27].decode("utf-8", "ignore")
    entry.cleaninfo = data[28].decode("utf-8", "ignore")
    entry.deleteinfo = data[29].decode("utf-8", "ignore")
    entry.backupod = data[30].decode("utf-8", "ignore")
    entry.parent = data[31].decode("utf-8", "ignore")
    entry.guid = data[32].decode("utf-8", "ignore")
    entry.clientgroup = data[33].decode("utf-8", "ignore")
    entry.address = data[34].decode("utf-8", "ignore")
    entry.domainname = data[35].decode("utf-8", "ignore")
    entry.ntdomain = data[36].decode("utf-8", "ignore")
    entry.macaddress = data[37].decode("utf-8", "ignore")
    entry.version = data[38].decode("utf-8", "ignore")
    entry.remotemachine = data[39].decode("utf-8", "ignore")
    entry.remotemachineip = data[40].decode("utf-8", "ignore")
    entry.action1status = data[41].decode("utf-8", "ignore")
    entry.action2status = data[42].decode("utf-8", "ignore")
    entry.licensefeaturename = data[43].decode("utf-8", "ignore")
    entry.licensefeatureversion = data[44].decode("utf-8", "ignore")
    entry.licenseserialnumber = data[45].decode("utf-8", "ignore")
    entry.licensefulfillmentid = data[46].decode("utf-8", "ignore")
    entry.licensestartdate = data[47].decode("utf-8", "ignore")
    entry.licenseexpirationdate = data[48].decode("utf-8", "ignore")
    entry.licenselifecycle = data[49].decode("utf-8", "ignore")
    entry.licenseseatstotal = data[50].decode("utf-8", "ignore")
    entry.licenseseats = data[51].decode("utf-8", "ignore")
    entry.errorcode = data[52].decode("utf-8", "ignore")
    entry.licenseseatsdelta = data[53].decode("utf-8", "ignore")
    entry.status = data[54].decode("utf-8", "ignore")
    entry.domainguid = data[55].decode("utf-8", "ignore")
    entry.sessionguid = data[56].decode("utf-8", "ignore")
    entry.vbnsessionid = data[57].decode("utf-8", "ignore")
    entry.logindomain = data[58].decode("utf-8", "ignore")
    entry.eventdata2 = data[59].decode("utf-8", "ignore")
    entry.erasercategoryid = log_eraser_category_id(data[60].decode("utf-8", "ignore"))
    entry.dynamiccategoryset = log_dynamic_categoryset_id(data[61].decode("utf-8", "ignore"))
    entry.subcategorysetid = data[62].decode("utf-8", "ignore")
    entry.displaynametouse = data[63].decode("utf-8", "ignore")
    entry.reputationdisposition = log_reputation_disposition(data[64].decode("utf-8", "ignore"))
    entry.reputationconfidence = data[65].decode("utf-8", "ignore")
    entry.firsseen = data[66].decode("utf-8", "ignore")
    entry.reputationprevalence = data[67].decode("utf-8", "ignore")
    entry.downloadurl = data[68].decode("utf-8", "ignore")
    entry.categoryfordropper = data[69].decode("utf-8", "ignore")
    entry.cidsstate = data[70].decode("utf-8", "ignore")
    entry.behaviorrisklevel = data[71].decode("utf-8", "ignore")
    entry.detectiontype = log_detection_type(data[72].decode("utf-8", "ignore"))
    entry.acknowledgetext = data[73].decode("utf-8", "ignore")
    entry.vsicstate = log_vsic_state(data[74].decode("utf-8", "ignore"))
    entry.scanguid = data[75].decode("utf-8", "ignore")
    entry.scanduration = data[76].decode("utf-8", "ignore")
    entry.scanstarttime = from_symantec_time(data[77].decode("utf-8", "ignore"))
    entry.targetapptype = log_target_app_type(data[78].decode("utf-8", "ignore"))
    entry.scancommandguid = data[79].decode("utf-8", "ignore")

    return f'"{entry.time}","{entry.event}","{entry.category}","{entry.logger}","{entry.computer}","{entry.user}","{entry.virus}","{entry.file}","{entry.wantedaction1}","{entry.wantedaction2}","{entry.realaction}","{entry.virustype}","{entry.flags}","{entry.description}","{entry.scanid}","{entry.newext}","{entry.groupid}","{entry.eventdata}","{entry.vbinid}","{entry.virusid}","{entry.quarantineforwardstatus}","{entry.access}","{entry.sdnstatus}","{entry.compressed}","{entry.depth}","{entry.stillinfected}","{entry.definfo}","{entry.defsequincenumber}","{entry.cleaninfo}","{entry.deleteinfo}","{entry.backupod}","{entry.parent}","{entry.guid}","{entry.clientgroup}","{entry.address}","{entry.domainname}","{entry.ntdomain}","{entry.macaddress}","{entry.version}","{entry.remotemachine}","{entry.remotemachineip}","{entry.action1status}","{entry.action2status}","{entry.licensefeaturename}","{entry.licensefeatureversion}","{entry.licenseserialnumber}","{entry.licensefulfillmentid}","{entry.licensestartdate}","{entry.licenseexpirationdate}","{entry.licenselifecycle}","{entry.licenseseatstotal}","{entry.licenseseats}","{entry.errorcode}","{entry.licenseseatsdelta}","{entry.status}","{entry.domainguid}","{entry.sessionguid}","{entry.vbnsessionid}","{entry.logindomain}","{entry.eventdata2}","{entry.erasercategoryid}","{entry.dynamiccategoryset}","{entry.subcategorysetid}","{entry.displaynametouse}","{entry.reputationdisposition}","{entry.reputationconfidence}","{entry.firsseen}","{entry.reputationprevalence}","{entry.downloadurl}","{entry.categoryfordropper}","{entry.cidsstate}","{entry.behaviorrisklevel}","{entry.detectiontype}","{entry.acknowledgetext}","{entry.vsicstate}","{entry.scanguid}","{entry.scanduration}","{entry.scanstarttime}","{entry.targetapptype}","{entry.scancommandguid}"'

def from_unix_sec(_):
    try:
        return datetime.utcfromtimestamp(int(_)).strftime('%Y-%m-%d %H:%M:%S')
    except:
        return datetime.utcfromtimestamp(0).strftime('%Y-%m-%d %H:%M:%S')

def from_win_64_hex(dateAndTime):
    """Convert a Windows 64 Hex Big-Endian value to a date"""
    base10_microseconds = int(dateAndTime, 16) / 10
    return datetime(1601,1,1) + timedelta(microseconds=base10_microseconds)

def from_symantec_time(timestamp):

    year, month, day_of_month, hours, minutes, seconds = (
        int(hexdigit[0] + hexdigit[1], 16) for hexdigit in zip(
            timestamp[::2], timestamp[1::2]))

    return datetime(year + 1970, month + 1, day_of_month, hours, minutes, seconds)        

def from_hex_ip(ipHex):
    ipHex = ipHex.decode("utf-8", "ignore")

    try:
        fourth, third, second, first = (
            int(hexdigit[0] + hexdigit[1], 16) for hexdigit in zip(
                ipHex[::2], ipHex[1::2]))

        return str(first) + '.' + str(second) + '.' + str(third) + '.' + str(fourth)

    except:
        return '0.0.0.0'

def from_hex_mac(macHex):

    one, two, three, four, five, six, _, _, _, _, _, _, _, _, _, _, = (
        hexdigit[0] + hexdigit[1] for hexdigit in zip(
            macHex[::2], macHex[1::2]))

    return str(one) + '-' + str(two) + '-' + str(three) + '-' + str(four) + '-' + str(five) + '-' + str(six)

def hexdump(buf, length=16):
    """Return a hexdump output string of the given buffer."""
    n = 0
    res = []

    while buf:
        line, buf = buf[:length], buf[length:]
        hexa = ' '.join(["{:02x}".format(x) for x in line])
        line = line.translate(__vis_filter).decode('utf-8')
        res.append('  %06x  %-*s %s' % (n, length * 3, hexa, line))
        n += length

    packet.write('\n'.join(res))
    packet.write('\n\n')
    return '\n'.join(res)

def parse_header(f):
    headersize = len(f.readline())
    f.seek(0)
    if headersize == 55:
        logType = 5
        logSize = read_unpack_hex(f, 0, 8)
        logEntries = read_unpack_hex(f, 18, 8)
        sepVer = read_unpack_hex(f, 45, 8)
        return logType, logEntries

    if headersize == 72:
        logType = read_unpack_hex(f, 0, 8)
        logSize = read_unpack_hex(f, 9, 8)
        logEntries = read_unpack_hex(f, 27, 8)
        sepVer = read_unpack_hex(f, 62, 8)
        return logType, logEntries

    try:
        try:
            from_symantec_time(f.readline().split(b',')[0].decode("utf-8", "ignore"))
            return 6, 1
        except:
            f.seek(388, 0)
            from_symantec_time(f.read(2048).split(b',')[0].decode("utf-8", "ignore"))
            return 7, 1

    except:
        print(f'Skipping {f.name}. Unknown File Type.\n')
        return 8, 1

def parse_syslog(f, logEntries):
    startEntry = 72
    nextEntry = read_unpack_hex(f, startEntry, 8)
    entry = LogFields()
    count = 0

    while True:
        data = '""' 
        logEntry = read_log_entry(f, startEntry, nextEntry).split(b'\t')
        entry.dateAndTime = from_win_64_hex(logEntry[1])
        entry.severity =  log_severity(int(logEntry[4], 16))
        entry.summary = logEntry[6].decode("utf-8", "ignore").replace('"', '""')
        entry.type = logEntry[7].decode("utf-8", "ignore")
        entry.size = ''

        if len(logEntry[8]) == 13:
            entry.size = int(logEntry[8][2:-3], 16)

        if len(logEntry[8]) > 13:
            data = read_log_data(logEntry[8])

        syslog.write(f'"{f.name}","{int(logEntry[0].decode("utf-8", "ignore"), 16)}","{entry.dateAndTime}","{logEntry[2].decode("utf-8", "ignore")}","{logEntry[3].decode("utf-8", "ignore")}","{entry.severity}","{entry.summary}","{logEntry[5].decode("utf-8", "ignore")}","{entry.type}","{entry.size}",{data}\n')
        count += 1

        if count == logEntries:
            break

        startEntry = startEntry + nextEntry
        nextEntry = read_unpack_hex(f, startEntry, 8)

def parse_seclog(f, logEntries):
    startEntry = 72
    nextEntry = read_unpack_hex(f, startEntry, 8)
    entry = LogFields()
    count = 0

    while True:
        logEntry = read_log_entry(f, startEntry, nextEntry).split(b'\t')
        entry.dateAndTime = from_win_64_hex(logEntry[1])
        entry.eventtype = sec_event_type(int(logEntry[2], 16))
        entry.severity =  log_severity(int(logEntry[3], 16))
        entry.localhost = from_hex_ip(logEntry[4])
        entry.remotehost = from_hex_ip(logEntry[5])
        entry.direction = log_direction(int(logEntry[8], 16))
        entry.endtime = from_win_64_hex(logEntry[9])
        entry.begintime = from_win_64_hex(logEntry[10])
        entry.occurrences = int(logEntry[11], 16)
        entry.description = logEntry[13].decode("utf-8", "ignore")
        entry.application = logEntry[15].decode("utf-8", "ignore")
        entry.protocol = ''
        entry.localmac = logEntry[17].hex()

        if len(entry.localmac) < 32:
            while True:
                logEntry[17] = logEntry[18] + b'\t'
                logEntry[17:19] = [b''.join(logEntry[17:19])]
                entry.localmac = logEntry[17].hex()

                if len(entry.localmac) == 32:
                    entry.localmac = from_hex_mac(logEntry[17].hex())
                    break

        else:
            entry.localmac = from_hex_mac(logEntry[17].hex())

        entry.remotemac = logEntry[18].hex()

        if len(entry.remotemac) < 32:
            while True:
                logEntry[18] = logEntry[18] + b'\t'
                logEntry[18:20] = [b''.join(logEntry[18:20])]
                entry.remotemac = logEntry[18].hex()

                if len(entry.remotemac) == 32:
                    entry.remotemac = from_hex_mac(logEntry[18].hex())
                    break

        else:
            entry.remotemac = from_hex_mac(logEntry[18].hex())

        entry.location = logEntry[19].decode("utf-8", "ignore")
        entry.user = logEntry[20].decode("utf-8", "ignore")
        entry.userdomain = logEntry[21].decode("utf-8", "ignore")
        entry.signatureid = int(logEntry[22], 16)
        entry.signaturesubid = int(logEntry[23], 16)
        entry.remoteport = int(logEntry[26], 16)
        entry.localport = int(logEntry[27], 16)
        entry.signaturename = logEntry[30].decode("utf-8", "ignore")
        entry.intrusionurl = logEntry[32].decode("utf-8", "ignore")
        entry.xintrusionpayloadurl = logEntry[31].decode("utf-8", "ignore")
        entry.protocol = ''
        entry.hash = logEntry[38].decode("utf-8", "ignore").strip('\r')
        seclog.write(f'"{f.name}","{int(logEntry[0].decode("utf-8", "ignore"), 16)}","{entry.dateAndTime}","{entry.eventtype}","{entry.severity}","{entry.direction}","{entry.protocol}","{entry.remotehost}","{entry.remoteport}","{entry.remotemac}","{entry.localhost}","{entry.localport}","{entry.localmac}","{entry.application}","{entry.signatureid}","{entry.signaturesubid}","{entry.signaturename}","{entry.intrusionurl}","{entry.xintrusionpayloadurl}","{entry.user}","{entry.userdomain}","{entry.location}","{entry.occurrences}","{entry.begintime}","{entry.endtime}","{entry.hash}","{entry.description}","{logEntry[6].decode("utf-8", "ignore")}","{logEntry[7].decode("utf-8", "ignore")}","{logEntry[12].decode("utf-8", "ignore")}","{logEntry[14].decode("utf-8", "ignore")}","{logEntry[16].decode("utf-8", "ignore")}","{logEntry[24].decode("utf-8", "ignore")}","{logEntry[25].decode("utf-8", "ignore")}","{logEntry[28].decode("utf-8", "ignore")}","{logEntry[29].decode("utf-8", "ignore")}","{logEntry[33].decode("utf-8", "ignore")}","{logEntry[34].decode("utf-8", "ignore")}","{logEntry[35].decode("utf-8", "ignore")}","{logEntry[36].decode("utf-8", "ignore")}","{logEntry[37].decode("utf-8", "ignore")}"\n')
        count += 1

        if count == logEntries:
            break

        startEntry = startEntry + nextEntry
        nextEntry = read_unpack_hex(f, startEntry, 8)

def parse_tralog(f, logEntries):
    startEntry = 72
    nextEntry = read_unpack_hex(f, startEntry, 8)
    entry = LogFields()
    count = 0

    while True:
        logEntry = read_log_entry(f, startEntry, nextEntry).split(b'\t')
        entry.dateAndTime = from_win_64_hex(logEntry[1])
        entry.protocol = protocol(int(logEntry[2].decode("utf-8", "ignore"), 16))
        entry.localhost = from_hex_ip(logEntry[3])
        entry.remotehost = from_hex_ip(logEntry[4])
        entry.localport = int(logEntry[5], 16)
        entry.remoteport = int(logEntry[6], 16)
        entry.direction = log_direction(int(logEntry[7], 16))
        entry.endtime = from_win_64_hex(logEntry[8])
        entry.begintime = from_win_64_hex(logEntry[9])
        entry.occurrences = int(logEntry[10], 16)
        entry.action = log_c_action(int(logEntry[11], 16))
        entry.severity = int(logEntry[13], 16)
        entry.rule = logEntry[16].decode("utf-8", "ignore")
        entry.application = logEntry[17].decode("utf-8", "ignore")
        entry.localmac = logEntry[18].hex()

        if len(entry.localmac) < 32:
            while True:
                logEntry[18] = logEntry[18] + b'\t'
                logEntry[18:20] = [b''.join(logEntry[18:20])]
                entry.localmac = logEntry[18].hex()

                if len(entry.localmac) == 32:
                    entry.localmac = from_hex_mac(logEntry[18].hex())
                    break

        else:
            entry.localmac = from_hex_mac(logEntry[18].hex())
        entry.remotemac = logEntry[19].hex()
        if len(entry.remotemac) < 32:
            while True:
                logEntry[19] = logEntry[19] + b'\t'
                logEntry[19:21] = [b''.join(logEntry[19:21])]
                entry.remotemac = logEntry[19].hex()
                if len(entry.remotemac) == 32:
                    entry.remotemac = from_hex_mac(logEntry[19].hex())
                    break

        else:
            entry.remotemac = from_hex_mac(logEntry[19].hex())

        entry.location = logEntry[20].decode("utf-8", "ignore")
        entry.user = logEntry[21].decode("utf-8", "ignore")
        entry.userdomain = logEntry[22].decode("utf-8", "ignore")
        tralog.write(f'"{f.name}","{int(logEntry[0].decode("utf-8", "ignore"), 16)}","{entry.dateAndTime}","{entry.action}","{entry.severity}","{entry.direction}","{entry.protocol}","{entry.remotehost}","{entry.remotemac}","{entry.remoteport}","{entry.localhost}","{entry.localmac}","{entry.localport}","{entry.application}","{entry.user}","{entry.userdomain}","{entry.location}","{entry.occurrences}","{entry.begintime}","{entry.endtime}","{entry.rule}","{logEntry[12].decode("utf-8", "ignore")}","{logEntry[14].decode("utf-8", "ignore")}","{logEntry[15].decode("utf-8", "ignore")}","{logEntry[23].decode("utf-8", "ignore")}","{logEntry[24].decode("utf-8", "ignore")}","{logEntry[25].decode("utf-8", "ignore")}","{logEntry[26].decode("utf-8", "ignore")}","{logEntry[27].decode("utf-8", "ignore")}","{logEntry[28].decode("utf-8", "ignore")}","{logEntry[29].decode("utf-8", "ignore")}","{logEntry[30].decode("utf-8", "ignore")}","{logEntry[31].decode("utf-8", "ignore")}"\n')
        count += 1

        if count == logEntries:
            break

        startEntry = startEntry + nextEntry
        nextEntry = read_unpack_hex(f, startEntry, 8)

def parse_raw(f, logEntries):
    startEntry = 72
    nextEntry = read_unpack_hex(f, startEntry, 8)
    entry = LogFields()
    count = 0

    while True:
        logEntry = read_log_entry(f, startEntry, nextEntry).split(b'\t')

        if len(logEntry) > 20:
            while True:
                logEntry[13] = logEntry[13] + b'\t'
                logEntry[13:15] = [b''.join(logEntry[13:15])]

                if len(logEntry) is 20:
                    break

        entry.dateAndTime = from_win_64_hex(logEntry[1])
        entry.localhost = from_hex_ip(logEntry[3])
        entry.remotehost = from_hex_ip(logEntry[4])
        entry.localport = int(logEntry[5], 16)
        entry.remoteport = int(logEntry[6], 16)
        entry.direction = ''
        entry.action = ''
        entry.application = logEntry[12].decode("utf-8", "ignore")
        entry.packetdecode = hexdump(logEntry[13]).replace('"', '""')
        entry.rule = logEntry[14].decode("utf-8", "ignore")
        entry.packetdump = ''
        rawlog.write(f'"{f.name}","{int(logEntry[0].decode("utf-8", "ignore"), 16)}","{entry.dateAndTime}","{entry.remotehost}","{entry.remoteport}","{entry.localhost}","{entry.localport}","{entry.direction}","{entry.action}","{entry.application}","{entry.rule}","{entry.packetdump}","{entry.packetdecode}","{logEntry[2].decode("utf-8", "ignore")}","{logEntry[7].decode("utf-8", "ignore")}","{logEntry[8].decode("utf-8", "ignore")}","{logEntry[9].decode("utf-8", "ignore")}","{logEntry[10].decode("utf-8", "ignore")}","{logEntry[11].decode("utf-8", "ignore")}","{logEntry[15].decode("utf-8", "ignore")}","{logEntry[16].decode("utf-8", "ignore")}","{logEntry[17].decode("utf-8", "ignore")}","{logEntry[18].decode("utf-8", "ignore")}","{logEntry[19].decode("utf-8", "ignore")}"\n')
        count += 1

        if count == logEntries:
            break

        startEntry = startEntry + nextEntry
        nextEntry = read_unpack_hex(f, startEntry, 8)

def parse_processlog(f, logEntries):
    startEntry = 72
    nextEntry = read_unpack_hex(f, startEntry, 3)
    entry = LogFields()
    count = 0

    while True:
        logEntry = read_log_entry(f, startEntry, nextEntry).split(b'\t')
        entry.dateAndTime = from_win_64_hex(logEntry[1])
        entry.severity = int(logEntry[3], 16)
        entry.action = log_c_action(int(logEntry[4], 16))
        entry.testmode = test_mode(logEntry[5].decode("utf-8", "ignore"))
        entry.description = logEntry[6].decode("utf-8", "ignore")
        entry.api = logEntry[7].decode("utf-8", "ignore")
        entry.rulename = logEntry[11].decode("utf-8", "ignore")
        entry.callerprocessid = int(logEntry[12], 16)
        entry.callerprocess = logEntry[13].decode("utf-8", "ignore")
        entry.target = logEntry[16].decode("utf-8", "ignore")
        entry.location = logEntry[17].decode("utf-8", "ignore")
        entry.user = logEntry[18].decode("utf-8", "ignore")
        entry.userdomain = logEntry[19].decode("utf-8", "ignore")
        entry.ipaddress = from_hex_ip(logEntry[22])
        entry.deviceinstanceid = logEntry[23].decode("utf-8", "ignore")
        entry.filesize = ''
        processlog.write(f'"{f.name}","{int(logEntry[0].decode("utf-8", "ignore"), 16)}","{entry.dateAndTime}","{entry.severity}","{entry.action}","{entry.testmode}","{entry.description}","{entry.api}","{entry.rulename}","{entry.ipaddress}","{entry.callerprocessid}","{entry.callerprocess}","{entry.deviceinstanceid}","{entry.target}","{entry.filesize}","{entry.user}","{entry.userdomain}","{entry.location}","{logEntry[2].decode("utf-8", "ignore")}","{logEntry[8].decode("utf-8", "ignore")}","{from_win_64_hex(logEntry[9])}","{from_win_64_hex(logEntry[10])}","{logEntry[14].decode("utf-8", "ignore")}","{logEntry[15].decode("utf-8", "ignore")}","{logEntry[20].decode("utf-8", "ignore")}","{logEntry[21].decode("utf-8", "ignore")}","{logEntry[24].decode("utf-8", "ignore")}","{logEntry[25].decode("utf-8", "ignore")}","{logEntry[26]}"\n')
        count += 1

        if count == logEntries:
            break

        startEntry = startEntry + nextEntry
        nextEntry = read_unpack_hex(f, startEntry, 3)

def parse_avman(f, logEntries):
    startEntry = 55
    nextEntry = read_unpack_hex(f, startEntry, 8)
    entry = LogFields()
    count = 0
    while True:
        logEntry = read_log_entry(f, startEntry, nextEntry).split(b'\t')
        dataLog = [w.replace(b'"', b'""') for w in logEntry[5].split(b',')]
        
        if log_event(dataLog[1].decode("utf-8", "ignore")) == 'SECURITY_SYMPROTECT_POLICYVIOLATION':
            parse_tamper_protect(dataLog, logEntry, f.name)

        if len(logEntry) < 32:
            diff = 32 - len(logEntry)
            b = [b''] * diff
            logEntry.extend(b)

        dataLog3 = [w.replace(b'"', b'""') for w in logEntry[17].split(b',')]
        dataLog4 = [w.replace(b'"', b'""') for w in logEntry[31].split(b',')]
        
        timeline.write(f'"{f.name}",')
        timeline.write(f'"{int(logEntry[0].decode("utf-8", "ignore"), 16)}","{from_win_64_hex(logEntry[1])}","{from_win_64_hex(logEntry[2])}","{from_win_64_hex(logEntry[3])}","{logEntry[4].decode("utf-8", "ignore")}",')

        if 'Summary' in log_category(dataLog[2].decode("utf-8", "ignore")):
            data = read_log_data(logEntry[5]).split(',')
            timeline.write(f'{",".join(data[0:18])},"","","","","","","","","","","","",{",".join(data[18:60])},"","","","","","","","","","","","","","",{",".join(data[60:81])}')

        else:
            timeline.write(f'"{from_symantec_time(dataLog[0].decode("utf-8", "ignore"))}","{log_event(dataLog[1].decode("utf-8", "ignore"))}","{log_category(dataLog[2].decode("utf-8", "ignore"))}","{log_logger(dataLog[3].decode("utf-8", "ignore"))}","{dataLog[4].decode("utf-8", "ignore")}","{dataLog[5].decode("utf-8", "ignore")}","{dataLog[6].decode("utf-8", "ignore")}","{dataLog[7].decode("utf-8", "ignore")}","{log_action(dataLog[8].decode("utf-8", "ignore"))}","{log_action(dataLog[9].decode("utf-8", "ignore"))}","{log_action(dataLog[10].decode("utf-8", "ignore"))}","{log_virus_type(dataLog[11].decode("utf-8", "ignore"))}","{log_flags(int(dataLog[12].decode("utf-8", "ignore")))}","{dataLog[13].decode("utf-8", "ignore")}","{dataLog[14].decode("utf-8", "ignore")}","{dataLog[15].decode("utf-8", "ignore")}","{dataLog[16].decode("utf-8", "ignore")}","{dataLog[17].decode("utf-8", "ignore")}",')
            timeline.write(f'"{logEntry[6].decode("utf-8", "ignore")}","{logEntry[7].decode("utf-8", "ignore")}","{log_tp_event(dataLog[17].decode("utf-8", "ignore"), logEntry[8].decode("utf-8", "ignore"))}","{logEntry[9].decode("utf-8", "ignore")}","{logEntry[10].decode("utf-8", "ignore")}","{logEntry[11].decode("utf-8", "ignore")}","{logEntry[12].decode("utf-8", "ignore")}",')

            if 'Security' in log_category(dataLog[2].decode("utf-8", "ignore")):
                dataLog2 = [w.replace('"', '""') for w in re.split(r',(?! )', logEntry[13].decode("utf-8", "ignore"))]

                if len(dataLog2) < 74:
                    diff = 74 - len(dataLog2)
                    b = [''] * diff
                    dataLog2.extend(b)

                timeline.write(f'"","","","{dataLog2[0]}","{dataLog2[0]}","{dataLog2[1]}","{dataLog2[2]}","{dataLog2[3]}","{dataLog2[4]}","{dataLog2[5]}","{dataLog2[6]}","{dataLog2[7]}","{dataLog2[8]}","{dataLog2[9]}","{dataLog2[10]}","{dataLog2[11]}","{dataLog2[12]}","{dataLog2[13]}","{dataLog2[14]}","{dataLog2[15]}","{dataLog2[16]}","{dataLog2[17]}","{dataLog2[18]}","{dataLog2[19]}","{dataLog2[20]}","{dataLog2[21]}","{dataLog2[22]}","{dataLog2[23]}","{dataLog2[24]}","{dataLog2[25]}","{dataLog2[26]}","{dataLog2[27]}","{dataLog2[28]}","{dataLog2[29]}","{dataLog2[30]}","{dataLog2[31]}","{dataLog2[32]}","{dataLog2[33]}","{dataLog2[34]}","{dataLog2[35]}","{dataLog2[36]}","{dataLog2[37]}","{dataLog2[38]}","{dataLog2[39]}","{dataLog2[40]}","{dataLog2[41]}","","","","","","","","","","","","","","","{dataLog2[42]}","{dataLog2[43]}","{log_dynamic_categoryset_id(dataLog2[44])}","{dataLog2[45]}","{dataLog2[46]}","{log_reputation_disposition(dataLog2[47])}","{dataLog2[48]}","{dataLog2[49]}","{dataLog2[50]}","{dataLog2[51]}","{dataLog2[52]}","{dataLog2[53]}","{dataLog2[54]}","{log_detection_type(dataLog2[55])}","{dataLog2[56]}","{log_vsic_state(dataLog2[57])}","{dataLog2[58]}","{dataLog2[59]}","{from_symantec_time(dataLog2[60])}","{dataLog2[61]}","{dataLog2[62]}","{dataLog2[63]}","{dataLog2[64]}","{dataLog2[65]}","{dataLog2[66]}","{dataLog2[67]}","{dataLog2[68]}","{dataLog2[69]}","{dataLog2[70]}","{from_unix_sec(dataLog2[71])}","{dataLog2[72]}","{dataLog2[73]}"')

            else:
                timeline.write(f'"{logEntry[13].decode("utf-8", "ignore")}",')
                timeline.write(f'"{logEntry[14].decode("utf-8", "ignore")}","{logEntry[15].decode("utf-8", "ignore")}","{logEntry[16].decode("utf-8", "ignore")}",')

                for entry in dataLog3:
                    entry = entry.replace(b'"', b'""')
                    timeline.write(f'"{entry.decode("utf-8", "ignore")}",')

                timeline.write(f'"{logEntry[18].decode("utf-8", "ignore")}","{logEntry[19].decode("utf-8", "ignore")}","{hash_type(logEntry[20].decode("utf-8", "ignore"))}","{logEntry[21].decode("utf-8", "ignore")}","{logEntry[22].decode("utf-8", "ignore")}","{logEntry[23].decode("utf-8", "ignore")}","{logEntry[24].decode("utf-8", "ignore")}","{logEntry[25].decode("utf-8", "ignore")}","{logEntry[26].decode("utf-8", "ignore")}","{logEntry[27].decode("utf-8", "ignore")}","{logEntry[28].decode("utf-8", "ignore")}","{logEntry[29].decode("utf-8", "ignore")}","{logEntry[30].decode("utf-8", "ignore")}",')

                try:
                    timeline.write(f'"{dataLog4[0].decode("utf-8", "ignore")}","{dataLog4[1].decode("utf-8", "ignore")}","{log_dynamic_categoryset_id(dataLog4[2].decode("utf-8", "ignore"))}","{dataLog4[3].decode("utf-8", "ignore")}","{dataLog4[4].decode("utf-8", "ignore")}","{log_reputation_disposition(dataLog4[5].decode("utf-8", "ignore"))}","{dataLog4[6].decode("utf-8", "ignore")}","{dataLog4[7].decode("utf-8", "ignore")}","{dataLog4[8].decode("utf-8", "ignore")}","{dataLog4[9].decode("utf-8", "ignore")}","{dataLog4[10].decode("utf-8", "ignore")}","{dataLog4[11].decode("utf-8", "ignore")}","{dataLog4[12].decode("utf-8", "ignore")}","{log_detection_type(dataLog4[13].decode("utf-8", "ignore"))}","{dataLog4[14].decode("utf-8", "ignore")}","{log_vsic_state(dataLog4[15].decode("utf-8", "ignore"))}","{dataLog4[16].decode("utf-8", "ignore")}","{dataLog4[17].decode("utf-8", "ignore")}","{from_symantec_time(dataLog4[18].decode("utf-8", "ignore"))}","{log_target_app_type(dataLog4[19].decode("utf-8", "ignore"))}","{dataLog4[20].decode("utf-8", "ignore")}","{dataLog4[21].decode("utf-8", "ignore")}","{dataLog4[22].decode("utf-8", "ignore")}","{dataLog4[23].decode("utf-8", "ignore")}","{dataLog4[24].decode("utf-8", "ignore")}","{dataLog4[25].decode("utf-8", "ignore")}","{dataLog4[26].decode("utf-8", "ignore")}","{dataLog4[27].decode("utf-8", "ignore")}","{dataLog4[28].decode("utf-8", "ignore")}","{from_unix_sec(int(dataLog4[29].decode("utf-8", "ignore")))}",')

                    iterdataLog = iter(dataLog4)
                    [next(iterdataLog) for x in range(30)]
                    for entry in iterdataLog:
                        timeline.write(f'"{entry.decode("utf-8", "ignore")}",')
                except:
                    for entry in dataLog4:
                        entry = entry.replace(b'"', b'""')
                        timeline.write(f'"{entry}",')

        timeline.write('\n')

        count += 1

        if count == logEntries:
            break

        startEntry = startEntry + nextEntry + 1
        nextEntry = read_unpack_hex(f, startEntry, 8)

def parse_tamper_protect(dataLog, logEntry, fname):
    # need action
    entry = LogFields()
    entry.action = ''
    entry.objecttype = ''
    entry.event = ''

    if dataLog[0] == '301':
        entry.computer = logEntry[4].replace('"', '')
        entry.user = logEntry[5].replace('"', '')
        entry.objecttype = log_tp_object_type(dataLog[5])
        entry.event = log_tp_event(dataLog[0], logEntry[17].split('\t')[3])
        entry.actor = f'{dataLog[2]} (PID {dataLog[1]})'
        entry.targetprocess = f'{dataLog[5]} (PID {dataLog[4]})'
        entry.target = dataLog[6]
        entry.time = logEntry[0].replace('"', '')

    else:
        entry.computer = dataLog[4].decode("utf-8", "ignore")
        entry.user = dataLog[5].decode("utf-8", "ignore")
        entry.objecttype = log_tp_object_type(logEntry[10].decode("utf-8", "ignore"))
        entry.event = log_tp_event(dataLog[17].decode("utf-8", "ignore"), logEntry[8].decode("utf-8", "ignore"))
        entry.actor = f'{logEntry[7].decode("utf-8", "ignore")} (PID {logEntry[6].decode("utf-8", "ignore")})'
        entry.targetprocess = f'{logEntry[10].decode("utf-8", "ignore")} (PID {logEntry[9].decode("utf-8", "ignore")})'
        entry.target = logEntry[11].decode("utf-8", "ignore")
        entry.time = from_symantec_time(dataLog[0].decode("utf-8", "ignore"))

    tamperProtect.write(f'"{fname}","{entry.computer}","{entry.user}","{entry.action}","{entry.objecttype}","{entry.event}","{entry.actor}","{entry.target}","{entry.targetprocess}","{entry.time}"\n')

def parse_daily_av(f, logType):
    
    if logType is 6:
        f.seek(0)
        logEntry = f.readline()
        
    else:
        f.seek(388, 0)
        logEntry = f.read(2048).rstrip(b'\x00')

    while logEntry:
        logEntry = read_log_data(logEntry)
        dataLog = logEntry.split('","')[17].split('\t')

        logEntry = logEntry.split(',')
        
        if logEntry[1] == '"SECURITY_SYMPROTECT_POLICYVIOLATION"':
            parse_tamper_protect(dataLog, logEntry, f.name)
            
        timeline.write(f'"{f.name}","","","","","",{logEntry[0]},{logEntry[1]},{logEntry[2]},{logEntry[3]},{logEntry[4]},{logEntry[5]},{logEntry[6]},{logEntry[7]},{logEntry[8]},{logEntry[9]},{logEntry[10]},{logEntry[11]},{logEntry[12]},{logEntry[13]},{logEntry[14]},{logEntry[15]},{logEntry[16]},')

        eventData1 = logEntry[17].split('\t')
        if len(eventData1) < 13:
                diff = 13 - len(eventData1)
                b = [''] * diff
                eventData1.extend(b)
        entry1 = eventData1[0].replace('"', '')
        
        timeline.write(f'"{entry1}","{eventData1[1]}","{eventData1[2]}","{log_tp_event(entry1, eventData1[3])}",')

        iterEventData1 = iter(eventData1)
        [next(iterEventData1) for x in range(4)]
        for entry in iterEventData1:
            entry = entry.replace('"', '')
            timeline.write(f'"{entry}",')

        timeline.write(f'{logEntry[18]},{logEntry[19]},{logEntry[20]},{logEntry[21]},{logEntry[22]},{logEntry[23]},{logEntry[24]},{logEntry[25]},{logEntry[26]},{logEntry[27]},{logEntry[28]},{logEntry[28]},{logEntry[30]},{logEntry[31]},{logEntry[32]},{logEntry[33]},{logEntry[34]},{logEntry[35]},{logEntry[36]},{logEntry[37]},{logEntry[38]},{logEntry[39]},{logEntry[40]},{logEntry[41]},{logEntry[42]},{logEntry[43]},{logEntry[44]},{logEntry[45]},{logEntry[46]},{logEntry[47]},{logEntry[48]},{logEntry[49]},{logEntry[50]},{logEntry[51]},{logEntry[52]},{logEntry[53]},{logEntry[54]},{logEntry[55]},{logEntry[56]},{logEntry[57]},{logEntry[58]},')

        eventData2 = logEntry[59].split('\t')
        if len(eventData1) < 15:
                diff = 15 - len(eventData2)
                b = [''] * diff
                eventData2.extend(b)
                
        eventData2[0] = eventData2[0].replace('"', '')
        
        timeline.write(f'"{eventData2[0]}","{eventData2[1]}","{eventData2[2]}","{hash_type(eventData2[3])}",')

        iterEventData2 = iter(eventData2)
        [next(iterEventData2) for x in range(4)]
        for entry in iterEventData2:
            entry = entry.replace('"', '')
            timeline.write(f'"{entry}",')

        timeline.write(f'{logEntry[60]},{logEntry[61]},{logEntry[62]},{logEntry[63]},{logEntry[64]},{logEntry[65]},{logEntry[66]},{logEntry[67]},{logEntry[68]},{logEntry[69]},{logEntry[70]},{logEntry[71]},{logEntry[72]},{logEntry[73]},{logEntry[74]},{logEntry[75]},{logEntry[76]},{logEntry[77]},{logEntry[78]},{logEntry[79]}')

        timeline.write('\n')
        
        if logType is 7:
            break
        logEntry = f.readline()

def main():


    for filename in filenames:
        print(f'Started parsing {filename}\n')
        try:
            with open(filename, 'rb') as f:
                logType, logEntries = parse_header(f)

                try:
                    if logEntries == 0:
                        print(f'Skipping {filename}. Log is empty.\n')
                        continue

                    if logType is 0:
                        parse_syslog(f, logEntries)
                        print(f'Finished parsing {filename}\n')

                    if logType is 1:
                        #missing eventtype, protocol, xintrusionpayloadurl

                        parse_seclog(f, logEntries)
                        print(f'Finished parsing {filename}\n')

                    if logType is 2:

                        parse_tralog(f, logEntries)
                        print(f'Finished parsing {filename}\n')

                    if logType is 3:

                        parse_raw(f, logEntries)
                        print(f'Finished parsing {filename}\n')

                    if logType is 4:
                        # file size unknown yet

                        parse_processlog(f, logEntries)
                        print(f'Finished parsing {filename}\n')

                    if logType is 5:

                        parse_avman(f, logEntries)
                        print(f'Finished parsing {filename}\n')

                    if logType is 6:

                        parse_daily_av(f, logType)
                        print(f'Finished parsing {filename}\n')
                        
                    if logType is 7:

                        parse_daily_av(f, logType)
                        print(f'Finished parsing {filename}\n')
#                        print('This is a quarantine file.')

                    else:
                        continue

                except Exception as e:
                    print(f'Problem parsing {filename}: {e}\n')
                    continue
                    
        except:
            print(f'Skipping {filename}. Access denied.\n')
        
        
        
    print(f'Processed {len(filenames)} file(s) in {format((time.time() - start), ".4f")} seconds')

start = time.time()
parser = argparse.ArgumentParser()
parser.add_argument("-f", "--file", help="file to be parsed")
parser.add_argument("-d", "--dir", help="directory to be parsed")
parser.add_argument("-k", "--kape", help="kape mode", action="store_true")
parser.add_argument("-o", "--output", help="directory to output files to. Default is current directory.")
parser.add_argument("-a", "--append", help="append to output files.", action="store_true")
args = parser.parse_args()

sep = ['Symantec Endpoint Protection\\CurrentVersion\\Data\\Logs', 'Symantec Endpoint Protection\\CurrentVersion\\Data\\Quarantine', 'Symantec Endpoint Protection\\Logs']
filenames = []

if args.kape or not (args.file or args.dir):
    print('Searching for Symantec logs.')
    rootDir = '/' 
    for path, subdirs, files in os.walk(rootDir):
        if any(x in path for x in sep):
            for name in files:
                filenames.append(os.path.join(path, name))
    
    if not filenames:
        print('No Symantec logs found.')
        sys.exit()

if args.file:
    filenames = [args.file]

if args.dir:
    print('Searching for Symantec logs.')
    root = args.dir
    for path, subdirs, files in os.walk(root):
        for name in files:
            filenames.append(os.path.join(path, name))

if args.output:
    if not os.path.exists(args.output):
            os.makedirs(args.output)
            
    if not args.append:
        syslog = open(args.output + '/Symantec_Client_Management_System_Log.csv', 'w')
        seclog = open(args.output + '/Symantec_Client_Management_Security_Log.csv', 'w')
        tralog = open(args.output + '/Symantec_Network_and_Host_Exploit_Mitigation_Traffic_Log.csv', 'w')
        rawlog = open(args.output + '/Symantec_Network_and_Host_Exploit_Mitigation_Packet_Log.csv', 'w')
        processlog = open(args.output + '/Symantec_Client_Management_Control_Log.csv', 'w')
        timeline = open(args.output + '/Symantec_Timeline.csv', 'w')
        packet = open(args.output + '/packet.txt', 'w')
        tamperProtect = open(args.output + '/Symantec_Client_Management_Tamper_Protect_Log.csv', 'w')
    else:
        syslog = open(args.output + '/Symantec_Client_Management_System_Log.csv', 'a')
        seclog = open(args.output + '/Symantec_Client_Management_Security_Log.csv', 'a')
        tralog = open(args.output + '/Symantec_Network_and_Host_Exploit_Mitigation_Traffic_Log.csv', 'a')
        rawlog = open(args.output + '/Symantec_Network_and_Host_Exploit_Mitigation_Packet_Log.csv', 'a')
        processlog = open(args.output + '/Symantec_Client_Management_Control_Log.csv', 'a')
        timeline = open(args.output + '/Symantec_Timeline.csv', 'a')
        packet = open(args.output + '/packet.txt', 'a')
        tamperProtect = open(args.output + '/Symantec_Client_Management_Tamper_Protect_Log.csv', 'a')
else:
    if not args.append:
        syslog = open('Symantec_Client_Management_System_Log.csv', 'w')
        seclog = open('Symantec_Client_Management_Security_Log.csv', 'w')
        tralog = open('Symantec_Network_and_Host_Exploit_Mitigation_Traffic_Log.csv', 'w')
        rawlog = open('Symantec_Network_and_Host_Exploit_Mitigation_Packet_Log.csv', 'w')
        processlog = open('Symantec_Client_Management_Control_Log.csv', 'w')
        timeline = open('Symantec_Timeline.csv', 'w')
        packet = open('packet.txt', 'w')
        tamperProtect = open('Symantec_Client_Management_Tamper_Protect_Log.csv', 'w')
    else:
        syslog = open('Symantec_Client_Management_System_Log.csv', 'a')
        seclog = open('Symantec_Client_Management_Security_Log.csv', 'a')
        tralog = open('Symantec_Network_and_Host_Exploit_Mitigation_Traffic_Log.csv', 'a')
        rawlog = open('Symantec_Network_and_Host_Exploit_Mitigation_Packet_Log.csv', 'a')
        processlog = open('Symantec_Client_Management_Control_Log.csv', 'a')
        timeline = open('Symantec_Timeline.csv', 'a')
        packet = open('packet.txt', 'a')
        tamperProtect = open('Symantec_Client_Management_Tamper_Protect_Log.csv', 'a')



if os.stat(timeline.name).st_size == 0:        
    csv_header()

if __name__ == "__main__":    
    main()