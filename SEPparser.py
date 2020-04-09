import os
import sys
import re
import time
import argparse
import binascii
from datetime import datetime,timedelta
import ctypes
import ipaddress
import xml.etree.ElementTree as ET
from dissect import cstruct
import struct
import SDDL3
import io
import ntpath

if os.name == 'nt':
    kernel32 = ctypes.windll.kernel32
    kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 7)

def csv_header():

    syslog.write('"File Name","Record Length","Date And Time","Event ID","Field4","Severity","summary","Event_Data_Size","Type","Size_(bytes)","LOG:Time(UTC)","LOG:Event","LOG:Category","LOG:Logger","LOG:Computer","LOG:User","LOG:Virus","LOG:File","LOG:WantedAction1","LOG:WantedAction2","LOG:RealAction","LOG:Virus_Type","LOG:Flags","LOG:Description","LOG:ScanID","LOG:New_Ext","LOG:Group_ID","LOG:Event_Data1","LOG:Event_Data2 (301_Actor PID)","LOG:Event_Data3 (301_Actor)","LOG:Event_Data4 (301_Event)","LOG:Event_Data5 (301_Target PID)","LOG:Event_Data6 (301_Target)","LOG:Event_Data7 (301_Target Process)","LOG:Event_Data8","LOG:Event_Data9","LOG:Event_Data10","LOG:Event_Data11","LOG:Event_Data12","LOG:Event_Data13","LOG:VBin_ID","LOG:Virus_ID","LOG:Quarantine_Forward_Status","LOG:Access","LOG:SDN_Status","LOG:Compressed","LOG:Depth","LOG:Still_Infected","LOG:Def_Info","LOG:Def_Sequence_Number","LOG:Clean_Info","LOG:Delete_Info","LOG:Backup_ID","LOG:Parent","LOG:GUID","LOG:Client_Group","LOG:Address","LOG:Domain_Name","LOG:NT_Domain","LOG:MAC_Address","LOG:Version","LOG:Remote_Machine","LOG:Remote_Machine_IP","LOG:Action_1_Status","LOG:Action_2_Status","LOG:License_Feature_Name","LOG:License_Feature_Version","LOG:License_Serial_Number","LOG:License_Fulfillment_ID","LOG:License_Start_Date","LOG:License_Expiration_Date","LOG:License_LifeCycle","LOG:License_Seats_Total","LOG:License_Seats","LOG:Error_Code","LOG:License_Seats_Delta","LOG:Status","LOG:Domain_GUID","LOG:Session_GUID","LOG:VBin_Session_ID","LOG:Login_Domain","LOG:Event_Data_2_1","LOG:Event_Data_2_Company_Name","LOG:Event_Data_2_Size (bytes)","LOG:Event_Data_2_Hash_Type","LOG:Event_Data_2_Hash","LOG:Event_Data_2_Product_Version","LOG:Event_Data_2_7","LOG:Event_Data_2_8","LOG:Event_Data_2_9","LOG:Event_Data_2_10","LOG:Event_Data_2_11","LOG:Event_Data_2_12","LOG:Event_Data_2_Product_Name","LOG:Event_Data_2_14","LOG:Event_Data_2_15","LOG:Event_Data_2_16","LOG:Event_Data_2_17","LOG:Eraser_Category_ID","LOG:Dynamic_Categoryset_ID","LOG:Subcategoryset_ID","LOG:Display_Name_To_Use","LOG:Reputation_Disposition","LOG:Reputation_Confidence","LOG:First_Seen","LOG:Reputation_Prevalence","LOG:Downloaded_URL","LOG:Creator_For_Dropper","LOG:CIDS_State","LOG:Behavior_Risk_Level","LOG:Detection_Type","LOG:Acknowledge_Text","LOG:VSIC_State","LOG:Scan_GUID","LOG:Scan_Duration","LOG:Scan_Start_Time","LOG:TargetApp","LOG:Scan_Command_GUID","Field115","Field116","Filed117","Digital_Signatures_Signer","Digital_Signatures_Issuer","Digital_Signatures_Certificate_Thumbprint","Field121","Digital_Signatures_Serial_Number","Digital_Signatures_Signing_Time","Field124","Field125","Field126","Field127","Field128"\n')

    seclog.write('"File Name","Record Length","DateAndTime","Event Type","Severity","Direction","Protocol","Remote Host","Remote Port","Remote MAC","Local Host","Local Port","Local MAC","Application","Signature ID","Signature SubID","Signature Name","Intrusion-URL","X-Intrusion-Payload-URL","User","User Domain","Location","Occurrences","End Time","Begin Time","SHA256_Hash","Description","Field8","Event_Data_Size","Field15","Field18","Field26","Field27","Remote Host IPV6","Local Host IPV6","Field35","Version","Profile_Serial_Number","Field38","MD5_Hash","LOG:Time(UTC)","LOG:Event","LOG:Category","LOG:Logger","LOG:Computer","LOG:User","LOG:Virus","LOG:File","LOG:WantedAction1","LOG:WantedAction2","LOG:RealAction","LOG:Virus_Type","LOG:Flags","LOG:Description","LOG:ScanID","LOG:New_Ext","LOG:Group_ID","LOG:Event_Data1","LOG:Event_Data2 (301_Actor PID)","LOG:Event_Data3 (301_Actor)","LOG:Event_Data4 (301_Event)","LOG:Event_Data5 (301_Target PID)","LOG:Event_Data6 (301_Target)","LOG:Event_Data7 (301_Target Process)","LOG:Event_Data8","LOG:Event_Data9","LOG:Event_Data10","LOG:Event_Data11","LOG:Event_Data12","LOG:Event_Data13","LOG:VBin_ID","LOG:Virus_ID","LOG:Quarantine_Forward_Status","LOG:Access","LOG:SDN_Status","LOG:Compressed","LOG:Depth","LOG:Still_Infected","LOG:Def_Info","LOG:Def_Sequence_Number","LOG:Clean_Info","LOG:Delete_Info","LOG:Backup_ID","LOG:Parent","LOG:GUID","LOG:Client_Group","LOG:Address","LOG:Domain_Name","LOG:NT_Domain","LOG:MAC_Address","LOG:Version","LOG:Remote_Machine","LOG:Remote_Machine_IP","LOG:Action_1_Status","LOG:Action_2_Status","LOG:License_Feature_Name","LOG:License_Feature_Version","LOG:License_Serial_Number","LOG:License_Fulfillment_ID","LOG:License_Start_Date","LOG:License_Expiration_Date","LOG:License_LifeCycle","LOG:License_Seats_Total","LOG:License_Seats","LOG:Error_Code","LOG:License_Seats_Delta","LOG:Status","LOG:Domain_GUID","LOG:Session_GUID","LOG:VBin_Session_ID","LOG:Login_Domain","LOG:Event_Data_2_1","LOG:Event_Data_2_Company_Name","LOG:Event_Data_2_Size (bytes)","LOG:Event_Data_2_Hash_Type","LOG:Event_Data_2_Hash","LOG:Event_Data_2_Product_Version","LOG:Event_Data_2_7","LOG:Event_Data_2_8","LOG:Event_Data_2_9","LOG:Event_Data_2_10","LOG:Event_Data_2_11","LOG:Event_Data_2_12","LOG:Event_Data_2_Product_Name","LOG:Event_Data_2_14","LOG:Event_Data_2_15","LOG:Event_Data_2_16","LOG:Event_Data_2_17","LOG:Eraser_Category_ID","LOG:Dynamic_Categoryset_ID","LOG:Subcategoryset_ID","LOG:Display_Name_To_Use","LOG:Reputation_Disposition","LOG:Reputation_Confidence","LOG:First_Seen","LOG:Reputation_Prevalence","LOG:Downloaded_URL","LOG:Creator_For_Dropper","LOG:CIDS_State","LOG:Behavior_Risk_Level","LOG:Detection_Type","LOG:Acknowledge_Text","LOG:VSIC_State","LOG:Scan_GUID","LOG:Scan_Duration","LOG:Scan_Start_Time","LOG:TargetApp","LOG:Scan_Command_GUID","Field115","Field116","Filed117","Digital_Signatures_Signer","Digital_Signatures_Issuer","Digital_Signatures_Certificate_Thumbprint","Field121","Digital_Signatures_Serial_Number","Digital_Signatures_Signing_Time","Field124","Field125","Field126","Field127","Field128"\n')

    tralog.write('"File Name","Record Length","Date and Time","Action","Severity","Direction","Protocol","Remote Host","Remote MAC","Remote Port","Local Host","Local MAC","Local Port","Application","User","User Domain","Location","Occurrences","Begin Time","End Time","Rule","Event Data Size","Rule ID","Event Data","Field24","Field25","Remote Host IPV6","Local Host IPV6","Field28","Field29","Hash:MD5","Hash:SHA256","Field32"\n')

    rawlog.write('"File Name","Recode Length","Date and Time","Remote Host","Remote Port","Local Host","Local Port","Direction","Action","Application","Rule","Packet Dump","Packet Decode","Event ID","Field8","Field9","Field10","Event Data Size","Event Data","Field16","Field17","Remote Host IPV6","Local Host IPV6","Rule ID"\n')

    processlog.write('"File Name","Record Length","Date And Time","Severity","Action","Test Mode","Description","API","Rule Name","IPV4 Address","IPV6 Address","Caller Process ID","Caller Process","Device Instance ID","Target","File Size","User","User Domain","Location","Event ID","Field9","Begin Time","End Time","Field15","Field16","Field21","Field22","Field25","Field26"\n')

    timeline.write('"File Name","Record Length","Date/Time1","Date/Time2","Date/Time3","Field5","LOG:Time(UTC)","LOG:Event","LOG:Category","LOG:Logger","LOG:Computer","LOG:User","LOG:Virus","LOG:File","LOG:WantedAction1","LOG:WantedAction2","LOG:RealAction","LOG:Virus_Type","LOG:Flags","LOG:Description","LOG:ScanID","LOG:New_Ext","LOG:Group_ID","LOG:Event_Data1","LOG:Event_Data2 (301_Actor PID)","LOG:Event_Data3 (301_Actor)","LOG:Event_Data4 (301_Event)","LOG:Event_Data5 (301_Target PID)","LOG:Event_Data6 (301_Target)","LOG:Event_Data7 (301_Target Process)","LOG:Event_Data8 (101_Virus)","LOG:Event_Data9","LOG:Event_Data10 (101_Remediation Type ID)","LOG:Event_Data11","LOG:Event_Data12","LOG:Event_Data13","LOG:VBin_ID","LOG:Virus_ID","LOG:Quarantine_Forward_Status","LOG:Access","LOG:SDN_Status","LOG:Compressed","LOG:Depth","LOG:Still_Infected","LOG:Def_Info","LOG:Def_Sequence_Number","LOG:Clean_Info","LOG:Delete_Info","LOG:Backup_ID","LOG:Parent","LOG:GUID","LOG:Client_Group","LOG:Address","LOG:Domain_Name","LOG:NT_Domain","LOG:MAC_Address","LOG:Version","LOG:Remote_Machine","LOG:Remote_Machine_IP","LOG:Action_1_Status","LOG:Action_2_Status","LOG:License_Feature_Name","LOG:License_Feature_Version","LOG:License_Serial_Number","LOG:License_Fulfillment_ID","LOG:License_Start_Date","LOG:License_Expiration_Date","LOG:License_LifeCycle","LOG:License_Seats_Total","LOG:License_Seats","LOG:Error_Code","LOG:License_Seats_Delta","LOG:Status","LOG:Domain_GUID","LOG:Session_GUID","LOG:VBin_Session_ID","LOG:Login_Domain","LOG:Event_Data_2_1","LOG:Event_Data_2_Company_Name","LOG:Event_Data_2_Size (bytes)","LOG:Event_Data_2_Hash_Type","LOG:Event_Data_2_Hash","LOG:Event_Data_2_Product_Version","LOG:Event_Data_2_7","LOG:Event_Data_2_8","LOG:Event_Data_2_9","LOG:Event_Data_2_10","LOG:Event_Data_2_11","LOG:Event_Data_2_12","LOG:Event_Data_2_Product_Name","LOG:Event_Data_2_14","LOG:Event_Data_2_15","LOG:Event_Data_2_16","LOG:Event_Data_2_17","LOG:Eraser_Category_ID","LOG:Dynamic_Categoryset_ID","LOG:Subcategoryset_ID","LOG:Display_Name_To_Use","LOG:Reputation_Disposition","LOG:Reputation_Confidence","LOG:First_Seen","LOG:Reputation_Prevalence","LOG:Downloaded_URL","LOG:Creator_For_Dropper","LOG:CIDS_State","LOG:Behavior_Risk_Level","LOG:Detection_Type","LOG:Acknowledge_Text","LOG:VSIC_State","LOG:Scan_GUID","LOG:Scan_Duration","LOG:Scan_Start_Time","LOG:TargetApp","LOG:Scan_Command_GUID","Field115","Field116","Filed117","Digital_Signatures_Signer","Digital_Signatures_Issuer","Digital_Signatures_Certificate_Thumbprint","Field121","Digital_Signatures_Serial_Number","Digital_Signatures_Signing_Time","Field124","Field125","Field126","Field127","Field128"\n')

    tamperProtect.write('"File Name","Computer","User","Action Taken","Object Type","Event","Actor","Target","Target Process","Date and Time"\n')
    
    quarantine.write('"File Name","Description","Record ID","Modify Date 1 UTC","Creation Date 1 UTC","Access Date 1 UTC","VBin Time 1 UTC","Storage Name","Storage Instance ID","Storage Key","File Size 1","Creation Date 2 UTC","Access Date 2 UTC","Modify Date 2 UTC","VBin Time 2 UTC","Unique ID","Record Type","Quarantine Session ID","Remediation Type","Wide Description","SDDL","SHA1","Quarantine Container Size","File Size 2","Detection Digest","Virus","GUID","Additional Info","Owner SID"\n')
    
    settings.write('"Log Name","Max Log Size","# of Logs","Max Log Days","Field3","Field5","Field6"\n')

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
    digitalsigner = ''
    digitalissuer = ''
    digitalthumbprint = ''
    digitalsn = ''
    digitaltime = ''
    action = ''
    objecttype = ''

VBN_DEF = """

typedef struct _VBN_METADATA_V1{
    int32 QFM_HEADER_Offset;
    char Description[384];
    char Log_line[984];
    int32 Data_Type1; //if 0x2 contains dates, if 0x1 no dates
    long Record_ID;
    char Date_Modified[8];
    char Date_Created[8];
    char Date_Accessed[8];
    int32 Data_Type2; //if 0x2 contains storage info, if 0x0 no storage info
    char Unknown1[484];
    char Storage_Name[48];
    int32 Storage_Instance_ID;
    char Storage_Key[384];
    int32 Data_Type3;
    int32 Unknown3;
    char Unknown4[8];
    int32 Data_Type4;
    int32 Quarantine_File_Size;
    int32 Date_Created_2;
    int32 Date_Accessed_2;
    int32 Date_Modified_2;
    int32 VBin_Time_2;
    char Unknown5[8];
    char Unique_ID[16];
    char Unknown6[260];
    int32 Unknown7;
    int32 Record_Type; 
    int32 Quarantine_Session_ID;
    int32 Remediation_Type;
    int32 Unknown9;
    int32 Unknown10;
    int32 Unknown11;
    int32 Unknown12;
    int32 Unknown13;
    int32 Unknown14;
    int32 Unknown15;
    wchar WDescription[384];
    char Unknown16[212];
} VBN_METADATA_V1;

typedef struct _VBN_METADATA_V2 {
    int32 QFM_HEADER_Offset;
    char Description[384];
    char Log_line[2048];
    int32 Data_Type1; //if 0x2 contains dates, if 0x1 no dates
    long Record_ID;
    char Date_Modified[8];
    char Date_Created[8];
    char Date_Accessed[8];
    int32 Data_Type2; //if 0x2 contains storage info, if 0x0 no storage info
    char Unknown1[484];
    char Storage_Name[48];
    int32 Storage_Instance_ID;
    char Storage_Key[384];
    int32 Data_Type3;
    int32 Unknown3;
    char Unknown4[8];
    int32 Data_Type4;
    int32 Quarantine_File_Size;
    int64 Date_Created_2;
    int64 Date_Accessed_2;
    int64 Date_Modified_2;
    int64 VBin_Time_2;
    char Unknown5[4];
    char Unique_ID[16];
    char Unknown6[260];
    int32 Unknown7;
    int32 Record_Type; 
    int32 Quarantine_Session_ID;
    int32 Remediation_Type;
    int32 Unknown9;
    int32 Unknown10;
    int32 Unknown11;
    int32 Unknown12;
    int32 Unknown13;
    int32 Unknown14;
    int32 Unknown15;
    wchar WDescription[384];
    char Unknown16[212];
} VBN_METADATA_V2;

typedef struct _VBN_METADATA_Linux{
    int32 QFM_HEADER_Offset;
    char Description[4096];
    char Log_line[1112];
    int32 Data_Type1; //if 0x2 contains dates, if 0x1 no dates
    long Record_ID;
    char Unknown[40];
    int32 Date_Modified;
    int32 Date_Created;
    int32 Date_Accessed;
    int32 VBin_Time;
    int32 Data_Type2; //if 0x2 contains storage info, if 0x0 no storage info
    char Unknown1[452];
    char Storage_Name[48];
    int32 Storage_Instance_ID;
    char Storage_Key[4096];
    int32 Data_Type3;
    int32 Unknown3;
    char Unknown4[44];
    int32 Data_Type4;
    int32 Quarantine_File_Size;
    int32 Date_Created_2;
    int32 Date_Accessed_2;
    int32 Date_Modified_2;
    int32 VBin_Time_2;
    char Unknown5[8];
    char Unique_ID[16];
    char Unknown6[4096];
    int32 Unknown7;
    int32 Record_Type; 
    int32 Quarantine_Session_ID;
    int32 Remediation_Type;
    int32 Unknown9;
    int32 Unknown10;
    int32 Unknown11;
    int32 Unknown12;
    int32 Unknown13;
    int32 Unknown14;
    int32 Unknown15;
    wchar WDescription[384];
    char Unknown16[212];
} VBN_METADATA_Linux;

typedef struct _Quarantine_File_Metadata_Header {
    int64 QFM_Header;
    int64 QFM_Header_Size;
    int64 QFM_Size;
    int64 QFM_Size_Header_Size;
    int64 Data_Size_From_End_of_QFM-to_End_of_VBN;
    char QFM[QFM_Size]  //Full structure to end
} Quarantine_File_Metadata_Header;

typedef struct _ASN1_1 {
    byte Tag;
    char Value[1];
} ASN1_1;

typedef struct _ASN1_4 {
    byte Tag;
    char Value[4];
} ASN1_4;

typedef struct _ASN1_8 {
    byte Tag;
    char Value[8];
} ASN1_8;

typedef struct _ASN1_String {
    byte Tag;
    int32 Data_Length;
    char Data[Data_Length];
} ASN1_String;

typedef struct _Quarantine_File_Info {
    byte Tag1;
    int32 Tag1_Data;
    byte Tag2;
    byte Tag2_Data;
    byte Tag3;
    int32 Hash_Size;
    char SHA1[Hash_Size]; //need to fix for wchar
    byte Tag4;
    int32 Tag4_Data;
    byte Tag5;
    int32 Tag5_Data;
    byte Tag6;
    int32 QFS_Size;
    char Quarantine_File_Size[QFS_Size];
} Quarantine_File_Info;

typedef struct _Quarantine_File_Info2 {
    byte Tag1;
    int32 Security_Descriptor_Size;
    char Security_Descriptor[Security_Descriptor_Size]; //need to fix for wchar
    byte Tag2;
    int32 Tag2_Data;
    byte Tag3;
    int64 Quarantine_File_Size;
} Quarantine_File_Info2;

typedef struct _Chunk {
    byte Data_Type;
    int32 Chunk_Size;
} Chunk;

typedef struct _Junk_Header {
    int64 Unknown1;
    int64 Size;
    char Unknown2[Size];
    char Unknown3[12];
    int32 File_Size;
    int64 Unknown4;
} Junk_Header;

typedef struct _Junk_Footer {
    int64 Unknown1;
    int64 Size;
    int32 Unknown2;
    char Unknown3[Size];
} Junk_Footer;

typedef struct _QData_Location {
    int64 Header;
    int64 Data_Offset;
    int64 Data_Size;
    int32 EOF;
    char Unknown2[Data_Offset -28];
} QData_Location;

typedef struct _QData_Info {
    int64 Header;
    int64 QData_Info_Size;
    char Data[QData_Info_Size -16];
} QData_Info;

"""

vbnstruct = cstruct.cstruct()
vbnstruct.load(VBN_DEF)

def xor(msg,key):
    return ''.join(chr(key ^ j) for j in msg)
    
def sddl_translate(string):
    target = 'service'
    _ = string + '\n\n'
    sec = SDDL3.SDDL(string, target)
    _ +='Type: ' + sec.sddl_type + '\n'

    if sec.owner_sid:
        _ += '\tOwner Name: ' + sec.owner_account + '\n'
        _ += '\tOwner SID: ' + sec.owner_sid + '\n\n'

    if sec.group_sid:
        _ += '\tGroup Name: ' + sec.group_account + '\n'
        _ += '\tGroup SID: ' + sec.group_sid + '\n\n'

    _ += '\tAccess Control Entries:\n\n'
    sec.acl #.sort(cmp=SDDL.SortAceByTrustee)
    for ace in sec.acl:
        _ += '\t\tTrustee: ' + ace.trustee + '\n'
        _ += '\t\tACE Type: ' + ace.ace_type + '\n'
        _ += '\t\tPerms:' + '\n'

        for perm in ace.perms:
            _ += '\t\t\t' + perm + '\n'

        if ace.flags:
            _ += '\t\tFlags:\n'

        for flag in ace.flags:
            _ += '\t\t\t' + flag + '\n\n'

        if ace.object_type:
            _ += '\t\tObject Type: ' + ace.object_type + '\n'

        if ace.inherited_type:
            _ += '\t\tInherited Type: ' + ace.inherited_type + '\n'

        _ += ''

    _ += ''
    return _

def sec_event_type(_):
    event_value = {
                   '209':'Host Integrity failed (TSLOG_SEC_NO_AV)',
                   '210':'Host Integrity passed (TSLOG_SEC_AV)',
                   '221':'Host Integrity failed but it was reported as PASS',
                   '237':'Host Integrity custom log entry',
                   #Firewall and IPS events:
                   '201':'Invalid traffic by rule',
                   '202':'Port Scan',
                   '203':'Denial-of-service attack',
                   '204':'Trojan horse',
                   '205':'Executable file changed',
                   '206':'Intrusion Prevention System (Intrusion Detected,TSLOG_SEC_INTRUSION_DETECTED)',
                   '207':'Active Response',
                   '208':'MAC Spoofing',
                   '211':'Active Response Disengaged',
                   '216':'Executable file change detected',
                   '217':'Executable file change accepted',
                   '218':'Executable file change denied',
                   '219':'Active Response Canceled',
                   '220':'Application Hijacking',
                   '249':'Browser Protection event',
                   #Application and Device control:
                   '238':'Device control disabled device',
                   '239':'Buffer Overflow Event',
                   '240':'Software protection has thrown an exception',
                   '241':'Not used',
                   '242':'Device control enabled the device',
                   #Memory Exploit Mitigation events:
                   '250':'Memory Exploit Mitigation blocked an event',
                   '251':'Memory Exploit Mitigation allowed an event'
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

def sec_severity(_):
    severity_value = {
                      range(0, 4):'Critical',
                      range(4, 8):'Major',
                      range(8, 12):'Minor',
                      range(12, 16):'Information'
                     }

    for k in severity_value:
        if _ in k:
            return severity_value[k]

    else:
        return _

def sys_severity(_):
    severity_value = {
                      '0':'Information',
                      '1':'Warning',
                      '2':'Error',
                      '3':'Fatal'
                     }

    for k, v in severity_value.items():
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
    try:
        if data[3].decode("utf-8", "ignore") is '2' and data[64].decode("utf-8", "ignore") is '1':
            return 'AP realtime defferd scanning'
    except:
        pass

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
                '15':'Partial Analysis',
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
                '98':'Suspicious',
                '99':'Details Pending',
                '100':'IDS Block',
                '101':'Firewall violation',
                '102':'Allowed by User',
                '110':'INTERESTING PROCESS CAL',
                '111':'INTERESTING PROCESS DETECTED',
                '200':'Attachment Stripped',
                '500':'Not Applicable',
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

def log_display_name_to_use(_):
    display = {
              '0':'Application Name',
              '1':'VID Virus Name'
              }

    for k, v in display.items():
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

def log_reputation_confidence(_):
    conf = {
           range(0, 10):'Unknown',
           range(10, 25):'Low',
           range(25, 65):'Medium',
           range(65, 100):'High',
           range(100, 200):'Extremely High'
           }

    for k in conf:
        if int(_) in k:
            return conf[k]

    else:
        return _

def log_reputation_prevalence(_):
    prev = {
           range(0, 1):'Unknown',
           range(1, 51):'Very Low',
           range(51, 101):'Low',
           range(101, 151):'Moderate',
           range(151, 201):'High',
           range(201, 256):'Very High',
           range(256, 356):'Extremely High'
           }

    for k in prev:
        if int(_) in k:
            return prev[k]

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
        
def cids_state(_):
    status = {
             '0':'Disabled',
             '1':'On',
             '2':'Not Installed',
             '3':'Disabled By Policy',
             '4':'Malfunctioning',
             '5':'Disabled As Unlicensed',
             '127':'Status Not Reported'
             }

    for k, v in status.items():
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
#VBN Remediation Type ID
    remType = {
               '0':'',
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

    for k, v in remType.items():
        if k == str(_):
            return v

    return _

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

def sec_event_id(_):
    eventid = {
                #Installation events Possible values are:
                '12070001':'Internal error',
                '12070101':'Install complete',
                '12070102':'Restart recommended',
                '12070103':'Restart required',
                '12070104':'Installation failed',
                '12070105':'Uninstallation complete',
                '12070106':'Uninstallation failed',
                '12071037':'Symantec Endpoint Protection installed',
                '12071038':'Symantec Firewall installed',
                '12071039':'Uninstall',
                '1207103A':'Uninstall rolled-back',
                #Service events Possible values are:
                '12070201':'Service starting',
                '12070202':'Service started',
                '12070203':'Service start failure',
                '12070204':'Service stopped',
                '12070205':'Service stop failure',
                '1207021A':'Attempt to stop service',
                #Configuration events Possible values are:
                '12070206':'Config import complete',
                '12070207':'Config import error',
                '12070208':'Config export complete',
                '12070209':'Config export error',
                #Host Integrity events Possible values are:
                '12070210':'Host Integrity disabled',
                '12070211':'Host Integrity enabled',
                '12070220':'NAP integration enabled',
                #Import events Possible values are:
                '12070214':'Successfully imported advanced rule',
                '12070215':'Failed to import advanced rule',
                '12070216':'Successfully exported advanced rule',
                '12070217':'Failed to export advanced rule',
                '1207021B':'Imported sylink',
                #Client events Possible values are:
                '12070218':'Client Engine enabled',
                '12070219':'Client Engine disabled',
                '12071046':'Proactive Threat Scanning is not supported on this platform',
                '12071047':'Proactive Threat Scanning load error',
                '12071048':'SONAR content load error',
                '12071049':'Allow application',
                #Server events Possible values are:
                '12070301':'Server connected',
                '12070302':'No server response',
                '12070303':'Server connection failed',
                '12070304':'Server disconnected',
                '120B0001':'Cannot reach server',
                '120B0002':'Reconnected to the server',
                '120b0003':'Automatic upgrade complete',
                #Policy events Possible values are:
                '12070306':'New policy received',
                '12070307':'New policy applied',
                '12070308':'New policy failed',
                '12070309':'Cannot download policy',
                '120B0005':'Cannot download policy',
                '1207030A':'Have latest policy',
                '120B0004':'Have latest policy',
                #Antivirus engine events Possible values are:
                '12071006':'Scan omission',
                '12071007':'Definition file loaded',
                '1207100B':'Virus behavior detected',
                '1207100C':'Configuration changed',
                '12071010':'Definition file download',
                '12071012':'Sent to quarantine server',
                '12071013':'Delivered to Symantec',
                '12071014':'Security Response backup',
                '12071015':'Scan aborted',
                '12071016':'Symantec Endpoint Protection Auto-Protect Load error',
                '12071017':'Symantec Endpoint Protection Auto-Protect enabled',
                '12071018':'Symantec Endpoint Protection Auto-Protect disabled',
                '1207101A':'Scan delayed',
                '1207101B':'Scan restarted',
                '12071027':'Symantec Endpoint Protection is using old virus definitions',
                '12071041':'Scan suspended',
                '12071042':'Scan resumed',
                '12071043':'Scan duration too short',
                '12071045':'Scan enhancements failed',
                #Licensing events Possible values are:
                '1207101E':'License warning',
                '1207101F':'License error',
                '12071020':'License in grace period',
                '12071023':'License installed',
                '12071025':'License up-to-date',
                #Security events Possible values are:
                '1207102B':'Computer not compliant with security policy',
                '1207102C':'Computer compliant with security policy',
                '1207102D':'Tamper attempt',
                '12071034':'Login failed',
                '12071035':'Login succeeded',
                #Submission events Possible values are:
                '12120001':'System message from centralized reputation',
                '12120002':'Authentication token failure',
                '12120003':'Reputation failure',
                '12120004':'Reputation network failure',
                '12130001':'System message from Submissions',
                '12130002':'Submissions failure',
                '12130003':'Intrusion prevention submission',
                '12130004':'Antivirus detection submission',
                '12130005':'Antivirus advanced heuristic detection submission',
                '12130006':'Manual user submission',
                '12130007':'SONAR heuristic submission',
                '12130008':'SONAR detection submission',
                '12130009':'File Reputation submission',
                '1213000A':'Client authentication token request',
                '1213000B':'LiveUpdate error submission',
                '1213000C':'Process data submission',
                '1213000D':'Configuration data submission',
                '1213000E':'Network data submission',
                #Other events Possible values are:
                '1207020A':'Email post OK',
                '1207020B':'Email post failure',
                '1207020C':'Update complete',
                '1207020D':'Update failure',
                '1207020E':'Manual location change',
                '1207020F':'Location changed',
                '12070212':'Old rasdll version detected',
                '12070213':'Auto-update postponed',
                '12070305':'Mode changed',
                '1207030B':'Cannot apply HI script',
                '1207030C':'Content Update Server',
                '1207030D':'Content Update Packet',
                '12070500':'System message from device control',
                '12070600':'System message from anti-buffer overflow driver',
                '12070700':'System message from network access component',
                '12070800':'System message from LiveUpdate',
                '12070900':'System message from GUP',
                '12072000':'System message from Memory Exploit Mitigation',
                '12072009':'Intensive Protection disabled',
                '1207200A':'Intensive Protection enabled',
                '12071021':'Access denied warning',
                '12071022':'Log forwarding error',
                '12071044':'Client moved',
                '12071036':'Access denied warning',
                '12071000':'Message from Intrusion Prevention',
                '12071050':'SONAR disabled',
                '12071051':'SONAR enabled'
                }

    for k, v in eventid.items():

        if k == _.upper():
            return v

    return _

def raw_event_id(_):

    eventid = {
              '401':'Raw Ethernet'
              }

    for k, v in eventid.items():

        if k == str(_):
            return v

def process_event_id(_):

    eventid = {
              '501':'Application Control Driver',
              '502':'Application Control Rules',
              '999':'Tamper Protection'
              }

    for k, v in eventid.items():

        if k == str(_):
            return v

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

def read_log_data(data, tz):
    entry = LogFields()
    data = re.split(b',(?=(?:[^\"]*\"[^\"]*\")*[^\"]*$)', data)
    print(len(data))
    field113 = ''
    field114 = ''
    field115 = ''
    field119 = ''
    field122 = ''
    field123 = ''
    field124 = ''
    field125 = ''
    field126 = ''
    entry.time = from_symantec_time(data[0].decode("utf-8", "ignore"), tz)
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
    entry.eventdata = event_data1(data[17].decode("utf-8", "ignore"))
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
    try:
        entry.eventdata2 = event_data2(data[59].decode("utf-8", "ignore"))
        entry.erasercategoryid = log_eraser_category_id(data[60].decode("utf-8", "ignore"))
        entry.dynamiccategoryset = log_dynamic_categoryset_id(data[61].decode("utf-8", "ignore"))
        entry.subcategorysetid = data[62].decode("utf-8", "ignore")
        entry.displaynametouse = log_display_name_to_use(data[63].decode("utf-8", "ignore"))
        entry.reputationdisposition = log_reputation_disposition(data[64].decode("utf-8", "ignore"))
        entry.reputationconfidence = log_reputation_confidence(data[65].decode("utf-8", "ignore"))
        entry.firsseen = data[66].decode("utf-8", "ignore")
        entry.reputationprevalence = log_reputation_prevalence(data[67].decode("utf-8", "ignore"))
        entry.downloadurl = data[68].decode("utf-8", "ignore")
        entry.categoryfordropper = data[69].decode("utf-8", "ignore")
        entry.cidsstate = cids_state(data[70].decode("utf-8", "ignore"))
        entry.behaviorrisklevel = data[71].decode("utf-8", "ignore")
        entry.detectiontype = log_detection_type(data[72].decode("utf-8", "ignore"))
        entry.acknowledgetext = data[73].decode("utf-8", "ignore")
        entry.vsicstate = log_vsic_state(data[74].decode("utf-8", "ignore"))
        entry.scanguid = data[75].decode("utf-8", "ignore")
        entry.scanduration = data[76].decode("utf-8", "ignore")
        entry.scanstarttime = from_symantec_time(data[77].decode("utf-8", "ignore"), tz)
        entry.targetapptype = log_target_app_type(data[78].decode("utf-8", "ignore"))
        entry.scancommandguid = data[79].decode("utf-8", "ignore")
    except:
        pass
    try:
        field113 = data[80].decode("utf-8", "ignore")
        field114 = data[81].decode("utf-8", "ignore")
        field115 = data[82].decode("utf-8", "ignore")
        entry.digitalsigner = data[83].decode("utf-8", "ignore").replace('"', '')
        entry.digitalissuer = data[84].decode("utf-8", "ignore")
        entry.digitalthumbprint = data[85].decode("utf-8", "ignore")
        field119 = data[86].decode("utf-8", "ignore")
        entry.digitalsn = data[87].decode("utf-8", "ignore")
        entry.digitaltime = from_unix_sec(data[88].decode("utf-8", "ignore"))
        field122 = data[89].decode("utf-8", "ignore")
        field123 = data[90].decode("utf-8", "ignore")
        field124 = data[91].decode("utf-8", "ignore")
        field125 = data[92].decode("utf-8", "ignore")
        field126 = data[93].decode("utf-8", "ignore")
    except:
        pass
     
    return f'"{entry.time}","{entry.event}","{entry.category}","{entry.logger}","{entry.computer}","{entry.user}","{entry.virus}","{entry.file}","{entry.wantedaction1}","{entry.wantedaction2}","{entry.realaction}","{entry.virustype}","{entry.flags}","{entry.description}","{entry.scanid}","{entry.newext}","{entry.groupid}","{entry.eventdata}","{entry.vbinid}","{entry.virusid}","{entry.quarantineforwardstatus}","{entry.access}","{entry.sdnstatus}","{entry.compressed}","{entry.depth}","{entry.stillinfected}","{entry.definfo}","{entry.defsequincenumber}","{entry.cleaninfo}","{entry.deleteinfo}","{entry.backupod}","{entry.parent}","{entry.guid}","{entry.clientgroup}","{entry.address}","{entry.domainname}","{entry.ntdomain}","{entry.macaddress}","{entry.version}","{entry.remotemachine}","{entry.remotemachineip}","{entry.action1status}","{entry.action2status}","{entry.licensefeaturename}","{entry.licensefeatureversion}","{entry.licenseserialnumber}","{entry.licensefulfillmentid}","{entry.licensestartdate}","{entry.licenseexpirationdate}","{entry.licenselifecycle}","{entry.licenseseatstotal}","{entry.licenseseats}","{entry.errorcode}","{entry.licenseseatsdelta}","{entry.status}","{entry.domainguid}","{entry.sessionguid}","{entry.vbnsessionid}","{entry.logindomain}","{entry.eventdata2}","{entry.erasercategoryid}","{entry.dynamiccategoryset}","{entry.subcategorysetid}","{entry.displaynametouse}","{entry.reputationdisposition}","{entry.reputationconfidence}","{entry.firsseen}","{entry.reputationprevalence}","{entry.downloadurl}","{entry.categoryfordropper}","{entry.cidsstate}","{entry.behaviorrisklevel}","{entry.detectiontype}","{entry.acknowledgetext}","{entry.vsicstate}","{entry.scanguid}","{entry.scanduration}","{entry.scanstarttime}","{entry.targetapptype}","{entry.scancommandguid}","{field113}","{field114}","{field115}","{entry.digitalsigner}","{entry.digitalissuer}","{entry.digitalthumbprint}","{field119}","{entry.digitalsn}","{entry.digitaltime}","{field122}","{field123}","{field124}","{field125}","{field126}"'

def read_sep_tag(_):
    _ = io.BytesIO(_)
    extra = False
    match = []
    dd = ''
    sddl = ''
    sid = ''
    guid = ''
    hit = None
    virus = None
    while True:
        try:
            code = struct.unpack("B", _.read(1))[0]
        except:
            break
        if code == 1 or code == 10:
            _.seek(-1,1)
            tag = vbnstruct.ASN1_1(_.read(2))
            if args.hex_dump:
                cstruct.dumpstruct(tag)
        elif code == 3 or code == 6:
            _.seek(-1,1)
            tag = vbnstruct.ASN1_4(_.read(5))
            if args.hex_dump:
                cstruct.dumpstruct(tag)
        elif code == 4:
            _.seek(-1,1)
            tag = vbnstruct.ASN1_8(_.read(9))
            if args.hex_dump:
                cstruct.dumpstruct(tag)
        else:
            if extra:
                size = struct.unpack("<I", _.read(4))[0]
                _.seek(-5,1)
                if code is 9 and size is 16:
                    tag = vbnstruct.ASN1_String(_.read(5 + size))
#                    if re.match(b'dE21\x13;3E\x89\x993\x99\x06\x88\xf5\xa9', tag.Data):
#                        print('yes')
                else:
                    tag = vbnstruct.ASN1_4(_.read(5))
                if args.hex_dump:
                    cstruct.dumpstruct(tag)
                extra = False
            else:
                size = struct.unpack("<I", _.read(4))[0]
                _.seek(-5,1)
                if code is 9 and size is 16:
                    extra = True
                tag = vbnstruct.ASN1_String(_.read(5 + size))
                if re.match(b'\xb9\x1f\x8a\\\\\xb75\\\D\x98\x03%\xfc\xa1W\^q', tag.Data):
                    hit = 'virus'
#                if re.match(b'dE21\x13;3E\x89\x993\x99\x06\x88\xf5\xa9', tag.Data):
#                    print('yes')
                if code is 7 or code is 8:
                    if hit is 'virus':
                        virus = tag.Data.decode('latin-1').replace("\x00", "")
                        hit = None
                    else:
                        match.append(tag.Data.decode('latin-1').replace("\x00", ""))
                if args.hex_dump:
                    cstruct.dumpstruct(tag)

    for a in match:
        if 'Detection Digest:' in a:
            match.remove(a)
            dd = a.replace('"', '""')
        try:
            sddl = sddl_translate(a)
            match.remove(a)
        except:
            pass
        rsid = re.match('^S-\d-(\d+-){1,14}\d+$', a)
        if rsid:
            sid = a
            match.remove(a)
        rguid = re.match('^(\{{0,1}([0-9a-fA-F]){8}-([0-9a-fA-F]){4}-([0-9a-fA-F]){4}-([0-9a-fA-F]){4}-([0-9a-fA-F]){12}\}{0,1})$', a)
        if rguid:
            guid = a
            match.remove(a)

    if virus is None and len(match) >= 6:
        virus = match[0]
        del match[0]

    return match, dd, sddl, sid, virus, guid

def event_data1(_):
    _ = _.replace('"', '').split('\t')
    if len(_) < 13:
            diff = 13 - len(_)
            b = [''] * diff
            _.extend(b)

    _ = '","'.join(_)

    return _

def event_data2(_):
    _ = _.replace('"', '').split('\t')
    if len(_) < 17:
            diff = 17 - len(_)
            b = [''] * diff
            _.extend(b)
    
    _[3] = hash_type(_[3])
    _ = '","'.join(_)

    return _

def from_unix_sec(_):
    try:
        return datetime.utcfromtimestamp(int(_)).strftime('%Y-%m-%d %H:%M:%S')
    except:
        return datetime.utcfromtimestamp(0).strftime('%Y-%m-%d %H:%M:%S')

def from_win_64_hex(dateAndTime):
    """Convert a Windows 64 Hex Big-Endian value to a date"""
    base10_microseconds = int(dateAndTime, 16) / 10
    dateAndTime = datetime(1601,1,1) + timedelta(microseconds=base10_microseconds)
    return dateAndTime.strftime('%Y-%m-%d %H:%M:%S.%f')

def from_symantec_time(timestamp, tz):

    year, month, day_of_month, hours, minutes, seconds = (
        int(hexdigit[0] + hexdigit[1], 16) for hexdigit in zip(
            timestamp[::2], timestamp[1::2]))

    timestamp = datetime(year + 1970, month + 1, day_of_month, hours, minutes, seconds) + timedelta(hours=tz)
    return timestamp.strftime('%Y-%m-%d %H:%M:%S')

def from_filetime(_):
    try:
        _ = datetime.utcfromtimestamp(float(_ - 116444736000000000) / 10000000).strftime('%Y-%m-%d %H:%M:%S.%f')
    except:
        _ = datetime(1601, 1, 1).strftime('%Y-%m-%d %H:%M:%S')
    return _
    
def from_hex_ip(ipHex):
    ipHex = ipHex.decode("utf-8", "ignore")
    if ipHex is '0':
        return '0.0.0.0'
    if len(ipHex) is not 8:
        ipHex = '0' + ipHex
    try:
        ipv4 = (
            int(hexdigit[0] + hexdigit[1], 16) for hexdigit in zip(
                ipHex[::2], ipHex[1::2]))
        
        return  '.'.join(map(str, reversed(list(ipv4))))

    except:
        return '0.0.0.0'

def from_hex_ipv6(ipHex):
    ipHex = ipHex.decode("utf-8", "ignore")
    chunks = [ipHex[i:i+2] for i in range(0, len(ipHex), 2)]
    try:
        ipv6 = (
            x[0] + x[1] for x in zip(
                chunks[1::2],chunks[::2]))
        
        return ipaddress.ip_address(':'.join(ipv6)).compressed

    except:
        return '::'

def from_hex_mac(macHex):
    mac = (
        hexdigit[0] + hexdigit[1] for hexdigit in zip(
            macHex[::2], macHex[1::2]))
            
    return '-'.join(map(str, mac))[0:17]

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

def flip(_):
    _ = (hexdigit[0] + hexdigit[1] for hexdigit in zip(
        _[::2], _[1::2]))
    _ = ''.join(map(str, reversed(list(_))))
    return _

def parse_header(f):
    headersize = len(f.readline())
    if headersize == 0:
        print(f'\033[1;33mSkipping {f.name}. Unknown File Type. \033[1;0m\n')
        return 9, 0, 0, 1, 0, 0, 0
    f.seek(0)
    if headersize == 55:
        logType = 5
        maxSize = read_unpack_hex(f, 0, 8)
        field3 = read_unpack_hex(f, 9, 8)
        logEntries = read_unpack_hex(f, 18, 8)
        field5 = read_unpack_hex(f, 27, 8)
        field6 = read_unpack_hex(f, 36, 8)
        maxDays = read_unpack_hex(f, 45, 8)
        return logType, maxSize, field3, logEntries, field5, field6, maxDays

    if headersize == 72:
        logType = read_unpack_hex(f, 0, 8)
        maxSize = read_unpack_hex(f, 9, 8)
        field3 = read_unpack_hex(f, 18, 8)
        logEntries = read_unpack_hex(f, 27, 8)
        field5 = read_unpack_hex(f, 36, 8)
        field6 = read_unpack_hex(f, 45, 16)
        maxDays = read_unpack_hex(f, 62, 8)
        return logType, maxSize, field3, logEntries, field5, field6, maxDays

    try:
        from_symantec_time(f.readline().split(b',')[0].decode("utf-8", "ignore"), 0)
        return 6, 0, 0, 1, 0, 0, 0
    except:
        pass
    try:
        f.seek(388, 0)
        from_symantec_time(f.read(2048).split(b',')[0].decode("utf-8", "ignore"), 0)
        return 7, 0, 0, 1, 0, 0, 0
    except:
        pass
    try:
        f.seek(4100, 0)
        from_symantec_time(f.read(2048).split(b',')[0].decode("utf-8", "ignore"), 0)
        return 8, 0, 0, 1, 0, 0, 0
    except:
        print(f'\033[1;33mSkipping {f.name}. Unknown File Type. \033[1;0m\n')
        return 9, 0, 0, 1, 0, 0, 0
        
def parse_syslog(f, logEntries):
    startEntry = 72
    nextEntry = read_unpack_hex(f, startEntry, 8)
    entry = LogFields()
    count = 0

    while True:
        data = '""'
        logEntry = read_log_entry(f, startEntry, nextEntry).split(b'\t')
        entry.dateAndTime = from_win_64_hex(logEntry[1])
        entry.severity =  sys_severity(int(logEntry[4], 16))
        entry.summary = logEntry[6].decode("utf-8", "ignore").replace('"', '""')
        entry.type = logEntry[7].decode("utf-8", "ignore")

        if len(logEntry[8]) == 13:
            entry.size = int(logEntry[8][2:-3], 16)

        if len(logEntry[8]) > 13:
            data = read_log_data(logEntry[8], 0)

        syslog.write(f'"{f.name}","{int(logEntry[0].decode("utf-8", "ignore"), 16)}","{entry.dateAndTime}","{sec_event_id(logEntry[2].decode("utf-8", "ignore"))}","{logEntry[3].decode("utf-8", "ignore")}","{entry.severity}","{entry.summary}","{int(logEntry[5].decode("utf-8", "ignore"), 16)}","{entry.type}","{entry.size}",{data}\n')

        if len(data) > 2:
            timeline.write(f'"{f.name}","","","","","",{data}\n')
        
        count += 1

        if count == logEntries:
            break

        startEntry = startEntry + nextEntry
        f.seek(startEntry)
        check = f.read(1)

        while check is not b'0':
            startEntry += 1
            f.seek(startEntry)
            check = f.read(1)

            if len(check) is 0:
                break

            if check is b'0':
                f.seek(startEntry)

        if len(check) is 0:
            print(f'\033[1;31mEntry mismatch: {count} entries found. Should be {logEntries}.\033[1;0m\n')
            break

        nextEntry = read_unpack_hex(f, startEntry, 8)

def parse_seclog(f, logEntries):
    startEntry = 72
    nextEntry = read_unpack_hex(f, startEntry, 8)
    entry = LogFields()
    count = 0

    while True:
        logEntry = read_log_entry(f, startEntry, nextEntry).split(b'\t',16)
        logData = []
        if int(logEntry[12], 16) is 0:
            logData = ['']
        else:
            logData = read_log_data(logEntry[16][:int(logEntry[12], 16)], 0).split(",")

        entry.dateAndTime = from_win_64_hex(logEntry[1])
        entry.eventtype = sec_event_type(int(logEntry[2], 16))
        entry.severity =  sec_severity(int(logEntry[3], 16))
        entry.localhost = from_hex_ip(logEntry[4])
        entry.remotehost = from_hex_ip(logEntry[5])
        entry.protocol = sec_network_protocol(int(logEntry[6], 16))
        entry.direction = log_direction(int(logEntry[8], 16))
        entry.endtime = from_win_64_hex(logEntry[9])
        entry.begintime = from_win_64_hex(logEntry[10])
        entry.occurrences = int(logEntry[11], 16)
        entry.description = logEntry[13].decode("utf-8", "ignore")
        entry.application = logEntry[15].decode("utf-8", "ignore")
        logEntry2 = logEntry[16][int(logEntry[12], 16):].split(b'\t')
        entry.localmac = logEntry2[1].hex()

        if len(entry.localmac) < 32:
            while True:
                logEntry2[1] = logEntry2[2] + b'\t'
                logEntry2[1:3] = [b''.join(logEntry2[1:3])]
                entry.localmac = logEntry2[1].hex()

                if len(entry.localmac) == 32:
                    entry.localmac = from_hex_mac(logEntry2[1].hex())
                    break

        else:
            entry.localmac = from_hex_mac(logEntry2[1].hex())

        entry.remotemac = logEntry2[2].hex()

        if len(entry.remotemac) < 32:
            while True:
                logEntry2[2] = logEntry2[2] + b'\t'
                logEntry2[2:4] = [b''.join(logEntry2[2:4])]
                entry.remotemac = logEntry2[2].hex()

                if len(entry.remotemac) == 32:
                    entry.remotemac = from_hex_mac(logEntry2[2].hex())
                    break

        else:
            entry.remotemac = from_hex_mac(logEntry2[2].hex())

        entry.location = logEntry2[3].decode("utf-8", "ignore")
        entry.user = logEntry2[4].decode("utf-8", "ignore")
        entry.userdomain = logEntry2[5].decode("utf-8", "ignore")
        entry.signatureid = int(logEntry2[6], 16)
        entry.signaturesubid = int(logEntry2[7], 16)
        entry.remoteport = int(logEntry2[10], 16)
        entry.localport = int(logEntry2[11], 16)
        REMOTE_HOST_IPV6 = from_hex_ipv6(logEntry2[12])
        LOCAL_HOST_IPV6 = from_hex_ipv6(logEntry2[13])
        entry.signaturename = logEntry2[14].decode("utf-8", "ignore")
        entry.xintrusionpayloadurl = logEntry2[15].decode("utf-8", "ignore")
        entry.intrusionurl = logEntry2[16].decode("utf-8", "ignore")
        entry.hash = logEntry2[22].decode("utf-8", "ignore").strip('\r')
        
        seclog.write(f'"{f.name}","{int(logEntry[0].decode("utf-8", "ignore"), 16)}","{entry.dateAndTime}","{entry.eventtype}","{entry.severity}","{entry.direction}","{entry.protocol}","{entry.remotehost}","{entry.remoteport}","{entry.remotemac}","{entry.localhost}","{entry.localport}","{entry.localmac}","{entry.application}","{entry.signatureid}","{entry.signaturesubid}","{entry.signaturename}","{entry.intrusionurl}","{entry.xintrusionpayloadurl}","{entry.user}","{entry.userdomain}","{entry.location}","{entry.occurrences}","{entry.begintime}","{entry.endtime}","{entry.hash}","{entry.description}","{logEntry[7].decode("utf-8", "ignore")}","{int(logEntry[12], 16)}","{logEntry[14].decode("utf-8", "ignore")}","{logEntry2[0].decode("utf-8", "ignore")}","{logEntry2[8].decode("utf-8", "ignore")}","{logEntry2[9].decode("utf-8", "ignore")}","{REMOTE_HOST_IPV6}","{from_hex_ipv6(logEntry2[12])}","{logEntry2[17].decode("utf-8", "ignore")}","{logEntry2[18].decode("utf-8", "ignore")}","{logEntry2[19].decode("utf-8", "ignore")}","{logEntry2[20].decode("utf-8", "ignore")}","{logEntry2[21].decode("utf-8", "ignore")}",{",".join(logData)}\n')

        if len(logData) > 1:
            timeline.write(f'"{f.name}","{int(logEntry[12], 16)}","","","","",{",".join(logData)}\n')

        count += 1

        if count == logEntries:
            break

        startEntry = startEntry + nextEntry
        f.seek(startEntry)
        check = f.read(1)

        while check is not b'0':
            startEntry += 1
            f.seek(startEntry)
            check = f.read(1)

            if len(check) is 0:
                break

            if check is b'0':
                startEntry -= 1

        if len(check) is 0:
            print(f'\033[1;31mEntry mismatch: {count} entries found. Should be {logEntries}.\033[1;0m\n')
            break

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
        entry.severity = sec_severity(int(logEntry[13], 16))
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
        f.seek(startEntry)
        check = f.read(1)
            
        while check is not b'0':
            startEntry += 1
            f.seek(startEntry)
            check = f.read(1)
            
            if len(check) is 0:
                break
            
            if check is b'0':
                f.seek(startEntry)

        if len(check) is 0:
                print(f'\033[1;31mEntry mismatch: {count} entries found. Should be {logEntries}.\033[1;0m\n')
                break

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
        eventId = raw_event_id(int(logEntry[2].decode("utf-8", "ignore"), 16))
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
        
        rawlog.write(f'"{f.name}","{int(logEntry[0].decode("utf-8", "ignore"), 16)}","{entry.dateAndTime}","{entry.remotehost}","{entry.remoteport}","{entry.localhost}","{entry.localport}","{entry.direction}","{entry.action}","{entry.application}","{entry.rule}","{entry.packetdump}","{entry.packetdecode}","{eventId}","{logEntry[7].decode("utf-8", "ignore")}","{logEntry[8].decode("utf-8", "ignore")}","{logEntry[9].decode("utf-8", "ignore")}","{logEntry[10].decode("utf-8", "ignore")}","{logEntry[11].decode("utf-8", "ignore")}","{logEntry[15].decode("utf-8", "ignore")}","{logEntry[16].decode("utf-8", "ignore")}","{logEntry[17].decode("utf-8", "ignore")}","{logEntry[18].decode("utf-8", "ignore")}","{logEntry[19].decode("utf-8", "ignore")}"\n')
        count += 1

        if count == logEntries:
            break

        startEntry = startEntry + nextEntry
        f.seek(startEntry)
        check = f.read(1)

#        while check is not b'0':
#            print(f'{check}\n')
#            startEntry += 1
#            f.seek(startEntry)
#            check = f.read(1)
#            if check is b'0':
#                startEntry -= 1

        if len(check) is 0:
            print(f'\033[1;31mEntry mismatch: {count} entries found. Should be {logEntries}.\033[1;0m\n')
            break

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
        ipv6 = from_hex_ipv6(logEntry[26])
        processlog.write(f'"{f.name}","{int(logEntry[0].decode("utf-8", "ignore"), 16)}","{entry.dateAndTime}","{entry.severity}","{entry.action}","{entry.testmode}","{entry.description}","{entry.api}","{entry.rulename}","{entry.ipaddress}","{ipv6}","{entry.callerprocessid}","{entry.callerprocess}","{entry.deviceinstanceid}","{entry.target}","{entry.filesize}","{entry.user}","{entry.userdomain}","{entry.location}","{process_event_id(int(logEntry[2].decode("utf-8", "ignore"), 16))}","{logEntry[8].decode("utf-8", "ignore")}","{from_win_64_hex(logEntry[9])}","{from_win_64_hex(logEntry[10])}","{logEntry[14].decode("utf-8", "ignore")}","{logEntry[15].decode("utf-8", "ignore")}","{logEntry[20].decode("utf-8", "ignore")}","{logEntry[21].decode("utf-8", "ignore")}","{logEntry[24].decode("utf-8", "ignore")}","{logEntry[25].decode("utf-8", "ignore")}"\n')
        count += 1

        if count == logEntries:
            break

        startEntry = startEntry + nextEntry
        f.seek(startEntry)
        check = f.read(1)
            
#        while check is not b'0':
#            print(f'{check}\n')
#            startEntry += 1
#            f.seek(startEntry)
#            check = f.read(1)
#            if check is b'0':
#                startEntry -= 1

        if len(check) is 0:
            print(f'\033[1;31mEntry mismatch: {count} entries found. Should be {logEntries}.\033[1;0m\n')
            break

        nextEntry = read_unpack_hex(f, startEntry, 3)

def parse_avman(f, logEntries):
    startEntry = 55
    nextEntry = read_unpack_hex(f, startEntry, 8)
    entry = LogFields()
    count = 0
    while True:
        logEntry = read_log_entry(f, startEntry, nextEntry).split(b'\t', 5)
        logData = read_log_data(logEntry[5], 0)

        if logData.split('","')[1] == 'SECURITY_SYMPROTECT_POLICYVIOLATION':
            parse_tamper_protect(logData.split('","'), logEntry, f.name)
        
        timeline.write(f'"{f.name}","{int(logEntry[0].decode("utf-8", "ignore"), 16)}","{from_win_64_hex(logEntry[1])}","{from_win_64_hex(logEntry[2])}","{from_win_64_hex(logEntry[3])}","{logEntry[4].decode("utf-8", "ignore")}",{logData}\n')

        count += 1

        if count == logEntries:
            break

        startEntry = startEntry + nextEntry + 1
        f.seek(startEntry)
        check = f.read(1)
            
        while check is not b'0':
            startEntry += 1
            f.seek(startEntry)
            check = f.read(1)

            if len(check) is 0:
                break

            if check is b'0':
                f.seek(startEntry)
                
        if len(check) is 0:
            print(f'\033[1;31mEntry mismatch: {count} entries found. Should be {logEntries}.\033[1;0m\n')
            break
                
        nextEntry = read_unpack_hex(f, startEntry, 8)

def parse_tamper_protect(logData, logEntry, fname):
    # need action
    entry = LogFields()
    
    entry.time = logData[0]
    entry.computer = logData[4]
    entry.user = logData[5]
    entry.objecttype = log_tp_object_type(logData[22])
    entry.event = log_tp_event(logData[17], logData[20])
    entry.actor = f'{logData[19]} (PID {logData[18]})'
    entry.targetprocess = f'{logData[22]} (PID {logData[21]})'
    entry.target = logData[23]

    tamperProtect.write(f'"{fname}","{entry.computer}","{entry.user}","{entry.action}","{entry.objecttype}","{entry.event}","{entry.actor}","{entry.target}","{entry.targetprocess}","{entry.time}\n')

def parse_daily_av(f, logType, tz):
    if logType is 6:
        f.seek(0)
        logEntry = f.readline()

    if logType is 7:
        f.seek(388, 0)
        logEntry = f.read(2048).split(b'\x00\x00')[0]

    if logType is 8:
        f.seek(4100, 0)
        logEntry = f.read(1112).split(b'\x00\x00')[0]

    while logEntry:
        logEntry = read_log_data(logEntry, tz)
        timeline.write(f'"{f.name}","","","","","",{logEntry}\n')

        if logType is 7 or 8:
            break
            
        logEntry = f.readline()

def parse_vbn(f):
    vbin = ''
    qfile = ''
    sddl = ''
    sha1 = ''
    fpath1 = ''
    fpath2 = ''
    fpath3 = ''
    dd = ''
    tags = []
    sid = ''
    virus = ''
    guid = ''
    garbage = None
    header = 0
    footer = 0
    qfs = 0
    junkfs = 0
    f.seek(0, 0)
    qfm_offset = struct.unpack('i', f.read(4))[0]
    f.seek(0, 0)

    if qfm_offset == 3676:
        vbnmeta = vbnstruct.VBN_METADATA_V1(f)
    if qfm_offset == 4752:
        vbnmeta = vbnstruct.VBN_METADATA_V2(f)
    if qfm_offset == 15100:
        vbnmeta = vbnstruct.VBN_METADATA_Linux(f)
        
    wDescription = vbnmeta.WDescription.rstrip('\0')
    description = vbnmeta.Description.rstrip(b'\x00').decode("utf-8", "ignore")
    storageName = vbnmeta.Storage_Name.rstrip(b'\x00').decode("utf-8", "ignore")
    storageKey = vbnmeta.Storage_Key.rstrip(b'\x00').decode("utf-8", "ignore")
    uniqueId = '{' + '-'.join([flip(vbnmeta.Unique_ID.hex()[:8]), flip(vbnmeta.Unique_ID.hex()[8:12]), flip(vbnmeta.Unique_ID.hex()[12:16]), vbnmeta.Unique_ID.hex()[16:20], vbnmeta.Unique_ID.hex()[20:32]]).upper() + '}'
    rtid = remediation_type_desc(vbnmeta.Remediation_Type)
    
    if args.hex_dump:
        cstruct.dumpstruct(vbnmeta)
    
    if vbnmeta.Record_Type is 0:
        test = xor(f.read(8), 0x5A).encode('latin-1')
        if test == b'\xce \xaa\xaa\x06\x00\x00\x00':
            if args.hex_dump:
                print('\n           #######################################################')
                print('           #######################################################')
                print('           ##                                                   ##')
                print('           ## The following data structures are xored with 0x5A ##')
                print('           ##                                                   ##')
                print('           #######################################################')
                print('           #######################################################\n')
            qdata_location_size = xor(f.read(4), 0x5A).encode('latin-1')
            qdata_location_size = struct.unpack('i', qdata_location_size)[0]
            f.seek(-12, 1)
            qdata_location = vbnstruct.QData_Location(xor(f.read(qdata_location_size), 0x5A).encode('latin-1'))
            if args.hex_dump:
                cstruct.dumpstruct(qdata_location)
            pos = vbnmeta.QFM_HEADER_Offset + qdata_location.Data_Offset
            file_size = qdata_location.Data_Size - qdata_location.Data_Offset
            f.seek(pos)
            if args.extract:
                print('\n           #######################################################')
                print('           #######################################################')
                print('           ##                                                   ##')
                print('           ##    Extracting quarantine file. Please wait....    ##')
                print('           ##                                                   ##')
                print('           #######################################################')
                print('           #######################################################\n')                    
                qfile = xor(f.read(file_size), 0x5A)

            f.seek(pos + file_size)
            #need to properly parse
            qdata_info = vbnstruct.QData_Info(xor(f.read(), 0x5A).encode('latin-1'))
            if args.hex_dump:
                cstruct.dumpstruct(qdata_info)

        else:
            f.seek(-8, 1)
            if args.extract:
                qfile = xor(f.read(), 0x5A)

    
    if vbnmeta.Record_Type is 1:
        tags, dd, sddl, sid, virus, guid = read_sep_tag(f.read())

        if args.extract:
            print(f'\033[1;31mRecord type 1 does not contain quarantine data. Unable to extract file.\033[1;0m\n')
    
    if vbnmeta.Record_Type is 2:
        f.seek(vbnmeta.QFM_HEADER_Offset, 0)
        f.seek(8, 1)
        qfm_size = xor(f.read(8), 0x5A).encode('latin-1')
        qfm_size = struct.unpack('q', qfm_size)[0]
        f.seek(-16, 1)
        qfm = vbnstruct.Quarantine_File_Metadata_Header(xor(f.read(qfm_size), 0x5A).encode('latin-1'))
        if args.hex_dump:
            print('\n           #######################################################')
            print('           #######################################################')
            print('           ##                                                   ##')
            print('           ## The following data structures are xored with 0x5A ##')
            print('           ##                                                   ##')
            print('           #######################################################')
            print('           #######################################################\n')
            cstruct.dumpstruct(qfm)
            print('\n           #######################################################')
            print('           #######################################################')
            print('           ##                                                   ##')
            print('           ##         Quarantine File Metadata Structure        ##')
            print('           ##                                                   ##')
            print('           #######################################################')
            print('           #######################################################\n')
        tags, dd, sddl, sid, virus, guid = read_sep_tag(xor(f.read(qfm.QFM_Size), 0x5A).encode('latin-1'))
        
        pos = qfm.QFM_Size_Header_Size + vbnmeta.QFM_HEADER_Offset
        f.seek(pos)
        f.seek(8, 1)
        qfi_size = xor(f.read(4), 0x5A).encode('latin-1')
        try:
            qfi_size = struct.unpack('i', qfi_size)[0]
            f.seek(pos)
            qfi = vbnstruct.Quarantine_File_Info(xor(f.read(qfi_size + 35), 0x5A).encode('latin-1'))
            sha1 = qfi.SHA1.decode('latin-1').replace("\x00", "")
            qfs = int.from_bytes(qfi.Quarantine_File_Size, 'little')
        except:
            f.seek(pos) 
            qfi = vbnstruct.Quarantine_File_Info(xor(f.read(7), 0x5A).encode('latin-1') + (b'\x00' * 20))
            
        if args.hex_dump:
            cstruct.dumpstruct(qfi)
            
        dataType = xor(f.read(1), 0x5A).encode('latin-1')
        
        if dataType is b'\x08':
            pos += 35 + qfi.Hash_Size
            f.seek(pos)
            qfi2_size = xor(f.read(4), 0x5A).encode('latin-1')
            qfi2_size = struct.unpack('i', qfi2_size)[0]
            f.seek(pos)
            qfi2 =  vbnstruct.Quarantine_File_Info2(xor(f.read(qfi2_size + 18), 0x5A).encode('latin-1'))
            sddl = sddl_translate(qfi2.Security_Descriptor.decode('latin-1').replace("\x00", ""))
            if args.hex_dump:
                cstruct.dumpstruct(qfi2)
            pos += 19 + qfi2.Security_Descriptor_Size
            f.seek(pos)
            
        elif dataType is b'\t':  #actually \x09
            garbage = qfs - vbnmeta.Quarantine_File_Size
            pos += 35 + qfi.Hash_Size
            f.seek(pos)
        
        try:
            chunk = vbnstruct.chunk(xor(f.read(5), 0x5A).encode('latin-1'))
            pos += 5
            f.seek(pos)
            if garbage is not None:
                junk = vbnstruct.Junk_Header(xor(f.read(1000), 0xA5).encode('latin-1'))
                junkfs = junk.File_Size
                if args.hex_dump:
                    cstruct.dumpstruct(junk)
                f.seek(pos)

            if args.hex_dump or args.extract:
                while True:
                    if chunk.Data_Type is 9:
                        if args.hex_dump:
                            cstruct.dumpstruct(chunk)
                        qfile += xor(f.read(chunk.Chunk_Size), 0xA5)

                        try:
                            pos += chunk.Chunk_Size
                            chunk = vbnstruct.chunk(xor(f.read(5), 0x5A).encode('latin-1'))
                            pos += 5
                            f.seek(pos)

                        except:
                            break

                    else:
                        break
        
                if garbage is not None:
                    header = junk.Size + 40
                    footer = garbage - header
                    qfs = len(qfile) - footer
                    f.seek(-footer, 2)
                    try:
                        jf = vbnstruct.Junk_Footer(xor(f.read(footer), 0xA5).encode('latin-1'))
                        if args.hex_dump:
                            cstruct.dumpstruct(jf)
                    except:
                        pass
 
        except:
            if args.extract:
                print(f'\033[1;31mDoes not contain quarantine data. Clean by Deletion.\033[1;0m\n')
                print(f'\033[1;32mFinished parsing {f.name} \033[1;0m\n')
            pass
 
    if args.extract and len(qfile) > 0:
        output = open(ntpath.basename(description) + '.vbn','wb+')
        if (header or qfs) == 0:
            output.write(bytes(qfile, encoding= 'latin-1'))
        else:
            output.write(bytes(qfile[header:qfs], encoding= 'latin-1'))
        
    if not (args.extract or args.hex_dump):
        try:
            modify = from_filetime(int(flip(vbnmeta.Date_Modified.hex()), 16))
            create = from_filetime(int(flip(vbnmeta.Date_Created.hex()), 16))
            access = from_filetime(int(flip(vbnmeta.Date_Accessed.hex()), 16))
        except:
            modify = from_unix_sec(vbnmeta.Date_Modified)
            create = from_unix_sec(vbnmeta.Date_Created)
            access = from_unix_sec(vbnmeta.Date_Accessed)
            vbin = from_unix_sec(vbnmeta.VBin_Time)
            
        quarantine.write(f'"{f.name}","{description}","{vbnmeta.Record_ID}","{modify}","{create}","{access}","{vbin}","{storageName}","{vbnmeta.Storage_Instance_ID}","{storageKey}","{vbnmeta.Quarantine_File_Size}","{from_unix_sec(vbnmeta.Date_Created_2)}","{from_unix_sec(vbnmeta.Date_Accessed_2)}","{from_unix_sec(vbnmeta.Date_Modified_2)}","{from_unix_sec(vbnmeta.VBin_Time_2)}","{uniqueId}","{vbnmeta.Record_Type}","{hex(vbnmeta.Quarantine_Session_ID)[2:].upper()}","{rtid}","{wDescription}","{sddl}","{sha1}","{qfs}","{junkfs}","{dd}","{virus}","{guid}","{tags}","{sid}"\n')

def utc_offset(_):
    tree = ET.parse(_)
    root = tree.getroot()
    
    for SSAUTC in root.iter('SSAUTC'):
        utc = SSAUTC.get('Bias')

    return int(utc)

def main():

    for filename in filenames:
        print(f'\033[1;35mStarted parsing {filename} \033[1;0m\n')
        try:
            with open(filename, 'rb') as f:
                logType, maxSize, field3, logEntries, field5, field6, maxDays = parse_header(f)
                try:
                    if logType <= 5:
                            settings.write(f'"{filename}","{maxSize}","{logEntries}","{maxDays}","{field3}","{field5}","{field6}"\n')
                    if logEntries == 0:
                        print(f'\033[1;33mSkipping {filename}. Log is empty. \033[1;0m\n')
                        continue

                    if logType is 0:
                        parse_syslog(f, logEntries)

                    if logType is 1:
                        parse_seclog(f, logEntries)

                    if logType is 2:
                        # missing event_data, event_data size, which ipv6 is which
                        parse_tralog(f, logEntries)

                    if logType is 3:
                        #missing direction, action, which ipv6 is which
                        parse_raw(f, logEntries)

                    if logType is 4:
                        # file size unknown yet
                        #need better parsing(missing data)
                        parse_processlog(f, logEntries)

                    if logType is 5:
                        parse_avman(f, logEntries)

                    if logType is 6:
                        parse_daily_av(f, logType, args.timezone)

                    if logType is 7:
                        parse_vbn(f)
                        if not (args.extract or args.hex_dump):
                            parse_daily_av(f, logType, args.timezone)
                        
                    if logType is 8:
                        parse_vbn(f)
                        if not (args.extract or args.hex_dump):
                            parse_daily_av(f, logType, args.timezone)

                    if logType is 9:
                        continue
                    
                    print(f'\033[1;32mFinished parsing {filename} \033[1;0m\n')

                except Exception as e:
                    print(f'\033[1;31mProblem parsing {filename}: {e} \033[1;0m\n')
                    continue

        except Exception as e:
            print(f'\033[1;33mSkipping {filename}. \033[1;31m{e}\033[1;0m\n')

    print(f'\033[1;37mProcessed {len(filenames)} file(s) in {format((time.time() - start), ".4f")} seconds \033[1;0m')
    sys.exit()

start = time.time()
parser = argparse.ArgumentParser()
parser.add_argument("-f", "--file", help="File to be parsed")
parser.add_argument("-d", "--dir", help="Directory to be parsed")
parser.add_argument("-e", "--extract", help="Extract quarantine file from VBN if present.", action="store_true")
parser.add_argument("-hd", "--hex-dump", help="Dump hex output of VBN to screen.", action="store_true")
parser.add_argument("-o", "--output", help="Directory to output files to. Default is current directory.")
parser.add_argument("-a", "--append", help="Append to output files.", action="store_true")
parser.add_argument("-r", "--registrationInfo", help="Path to registrationInfo.xml")
parser.add_argument("-tz", "--timezone", type=int, help="UTC offset")
parser.add_argument("-k", "--kape", help="Kape mode", action="store_true")
args = parser.parse_args()

regex =  re.compile(r'\\Symantec Endpoint Protection\\(Logs|.*\\Data\\Logs|.*\\Data\\Quarantine)')
filenames = []

if args.hex_dump and not args.file:
    print("\n\033[1;31m-e, --extract and/or -hd, --hexdump can only be used with -f, --file.\033[1;0m\n")
    sys.exit()

if args.registrationInfo:
    try:
        print('\033[1;36mAttempting to apply timezone offset.\n \033[1;0m')
        args.timezone = utc_offset(args.registrationInfo)
        print(f'\033[1;32mTimezone offset of {args.timezone} applied successfully. \033[1;0m\n')
    except Exception as e:
        print(f'\033[1;31mUnable to apply offset. Timestamps will not be adjusted. {e}\033[1;0m\n')
        pass

if args.kape or not (args.file or args.dir):
    print('\nSearching for Symantec logs.\n')
    rootDir = '/'
    if args.dir:
        rootDir = args.dir
    for path, subdirs, files in os.walk(rootDir):
        if args.timezone is None and 'Symantec Endpoint Protection' in path and 'registrationInfo.xml' in files:
            for name in files:
                if name == 'registrationInfo.xml':
                    try:
                        print(f'\033[1;36m{ntpath.join(path, name)} found. Attempting to apply timezone offset.\n \033[1;0m')
                        args.timezone = utc_offset(ntpath.join(path, name))
                        print(f'\033[1;32mTimezone offset of {args.timezone} applied successfully. \033[1;0m\n')
                    except Exception as e:
                        print(f'\033[1;31mUnable to apply offset. Timestamps will not be adjusted. {e}\033[1;0m\n')
                        pass

        if regex.findall(path):
            for name in files:
                filenames.append(ntpath.join(path, name))

    if not filenames:
        print('No Symantec logs found.')
        sys.exit()

if args.file:
    filenames = [args.file]

if args.dir and not args.kape:
    print('\nSearching for Symantec logs.\n')
    root = args.dir
    for path, subdirs, files in os.walk(root):
        for name in files:
            if args.timezone is None and name == 'registrationInfo.xml':
                try:
                    print(f'\033[1;36m{ntpath.join(path, name)} found. Attempting to apply timezone offset.\n \033[1;0m')
                    args.timezone = utc_offset(ntpath.join(path, name))
                    print(f'\033[1;32mTimezone offset of {args.timezone} applied successfully. \033[1;0m\n')
                except Exception as e:
                    print(f'\033[1;31mUnable to apply offset. Timestamps will not be adjusted. {e}\033[1;0m\n')
                    pass

            filenames.append(ntpath.join(path, name))

if args.timezone is None:
    args.timezone = 0

if args.output and not (args.extract or args.hex_dump):
    if not ntpath.exists(args.output):
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
        quarantine = open(args.output + '/quarantine.csv', 'w')
        settings = open(args.output + '/settings.csv', 'w')
    else:
        syslog = open(args.output + '/Symantec_Client_Management_System_Log.csv', 'a')
        seclog = open(args.output + '/Symantec_Client_Management_Security_Log.csv', 'a')
        tralog = open(args.output + '/Symantec_Network_and_Host_Exploit_Mitigation_Traffic_Log.csv', 'a')
        rawlog = open(args.output + '/Symantec_Network_and_Host_Exploit_Mitigation_Packet_Log.csv', 'a')
        processlog = open(args.output + '/Symantec_Client_Management_Control_Log.csv', 'a')
        timeline = open(args.output + '/Symantec_Timeline.csv', 'a')
        packet = open(args.output + '/packet.txt', 'a')
        tamperProtect = open(args.output + '/Symantec_Client_Management_Tamper_Protect_Log.csv', 'a')
        quarantine = open(args.output + '/quarantine.csv', 'a')
        settings = open(args.output + '/settings.csv', 'a')
        
    if os.stat(timeline.name).st_size == 0:
        csv_header()
    
elif not (args.extract or args.hex_dump):
    if not args.append:
        syslog = open('Symantec_Client_Management_System_Log.csv', 'w')
        seclog = open('Symantec_Client_Management_Security_Log.csv', 'w')
        tralog = open('Symantec_Network_and_Host_Exploit_Mitigation_Traffic_Log.csv', 'w')
        rawlog = open('Symantec_Network_and_Host_Exploit_Mitigation_Packet_Log.csv', 'w')
        processlog = open('Symantec_Client_Management_Control_Log.csv', 'w')
        timeline = open('Symantec_Timeline.csv', 'w')
        packet = open('packet.txt', 'w')
        tamperProtect = open('Symantec_Client_Management_Tamper_Protect_Log.csv', 'w')
        quarantine = open('quarantine.csv', 'w')
        settings = open('settings.csv', 'w')
    else:
        syslog = open('Symantec_Client_Management_System_Log.csv', 'a')
        seclog = open('Symantec_Client_Management_Security_Log.csv', 'a')
        tralog = open('Symantec_Network_and_Host_Exploit_Mitigation_Traffic_Log.csv', 'a')
        rawlog = open('Symantec_Network_and_Host_Exploit_Mitigation_Packet_Log.csv', 'a')
        processlog = open('Symantec_Client_Management_Control_Log.csv', 'a')
        timeline = open('Symantec_Timeline.csv', 'a')
        packet = open('packet.txt', 'a')
        tamperProtect = open('Symantec_Client_Management_Tamper_Protect_Log.csv', 'a')
        quarantine = open('quarantine.csv', 'a')
        settings = open('settings.csv', 'a')

    if os.stat(timeline.name).st_size == 0:
        csv_header()

if __name__ == "__main__":
    main()