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
import base64
import json
import blowfish
import zlib

if os.name == 'nt':
    kernel32 = ctypes.windll.kernel32
    kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 7)

def csv_header():

    syslog.write('"File Name","Entry Length","Date And Time","Event ID","Field4","Severity","Summary","Event_Data_Size","Event_Source","Size_(bytes)","Location","LOG:Time","LOG:Event","LOG:Category","LOG:Logger","LOG:Computer","LOG:User","LOG:Virus","LOG:File","LOG:WantedAction1","LOG:WantedAction2","LOG:RealAction","LOG:Virus_Type","LOG:Flags","LOG:Description","LOG:ScanID","LOG:New_Ext","LOG:Group_ID","LOG:Event_Data1","LOG:Event_Data2_Label","LOG:Event_Data2","LOG:Event_Data3_Label","LOG:Event_Data3","LOG:Event_Data4_Label","LOG:Event_Data4","LOG:Event_Data5_Label","LOG:Event_Data5","LOG:Event_Data6_Label","LOG:Event_Data6","LOG:Event_Data7_Label","LOG:Event_Data7","LOG:Event_Data8_Label","LOG:Event_Data8","LOG:Event_Data9_Label","LOG:Event_Data9","LOG:Event_Data10_Label","LOG:Event_Data10","LOG:Event_Data11_Label","LOG:Event_Data11","LOG:Event_Data12_Label","LOG:Event_Data12","LOG:Event_Data13_Label","LOG:Event_Data13","LOG:VBin_ID","LOG:Virus_ID","LOG:Quarantine_Forward_Status","LOG:Access","LOG:SDN_Status","LOG:Compressed","LOG:Depth","LOG:Still_Infected","LOG:Def_Info","LOG:Def_Sequence_Number","LOG:Clean_Info","LOG:Delete_Info","LOG:Backup_ID","LOG:Parent","LOG:GUID","LOG:Client_Group","LOG:Address","LOG:Domain_Name","LOG:NT_Domain","LOG:MAC_Address","LOG:Version","LOG:Remote_Machine","LOG:Remote_Machine_IP","LOG:Action_1_Status","LOG:Action_2_Status","LOG:License_Feature_Name","LOG:License_Feature_Version","LOG:License_Serial_Number","LOG:License_Fulfillment_ID","LOG:License_Start_Date","LOG:License_Expiration_Date","LOG:License_LifeCycle","LOG:License_Seats_Total","LOG:License_Seats","LOG:Error_Code","LOG:License_Seats_Delta","Log:Eraser Status","LOG:Domain_GUID","LOG:Session_GUID","LOG:VBin_Session_ID","LOG:Login_Domain","LOG:Event_Data_2_1","LOG:Event_Data_2_Company_Name","LOG:Event_Data_2_Size (bytes)","LOG:Event_Data_2_Hash_Type","LOG:Event_Data_2_Hash","LOG:Event_Data_2_Product_Version","LOG:Event_Data_2_7","LOG:Event_Data_2_8","LOG:Event_Data_2_9","LOG:Event_Data_2_10","LOG:Event_Data_2_11","LOG:Event_Data_2_12","LOG:Event_Data_2_Product_Name","LOG:Event_Data_2_14","LOG:Event_Data_2_15","LOG:Event_Data_2_16","LOG:Event_Data_2_17","LOG:Eraser_Category_ID","LOG:Dynamic_Categoryset_ID","LOG:Subcategoryset_ID","LOG:Display_Name_To_Use","LOG:Reputation_Disposition","LOG:Reputation_Confidence","LOG:First_Seen","LOG:Reputation_Prevalence","LOG:Downloaded_URL","LOG:Creator_For_Dropper","LOG:CIDS_State","LOG:Behavior_Risk_Level","LOG:Detection_Type","LOG:Acknowledge_Text","LOG:VSIC_State","LOG:Scan_GUID","LOG:Scan_Duration","LOG:Scan_Start_Time","LOG:TargetApp","LOG:Scan_Command_GUID","LOG:Field113","LOG:Location","LOG:Field115","LOG:Digital_Signatures_Signer","LOG:Digital_Signatures_Issuer","LOG:Digital_Signatures_Certificate_Thumbprint","LOG:Field119","LOG:Digital_Signatures_Serial_Number","LOG:Digital_Signatures_Signing_Time","LOG:Field122","LOG:Field123","LOG:Field124","LOG:Field125","LOG:Field126"\n')

    seclog.write('"File Name","Entry Length","Date And Time","Event ID","Severity","Direction","Protocol","Remote Host","Remote Port","Remote MAC","Local Host","Local Port","Local MAC","Application","Signature ID","Signature SubID","Signature Name","Intrusion URL","X Intrusion Payload","User","User Domain","Location","Occurrences","End Time","Begin Time","SHA256 Hash","Description","Field8","Log Data Size","Field15","Field25","Field26","Remote Host IPV6","Local Host IPV6","Field34","Symantec Version Number","Profile Serial Number","Field37","MD5 Hash","URL HID Level","URL Risk Score","URL Categories","Data","LOG:Time","LOG:Event","LOG:Category","LOG:Logger","LOG:Computer","LOG:User","LOG:Virus","LOG:File","LOG:WantedAction1","LOG:WantedAction2","LOG:RealAction","LOG:Virus_Type","LOG:Flags","LOG:Description","LOG:ScanID","LOG:New_Ext","LOG:Group_ID","LOG:Event_Data1","LOG:Event_Data2_Label","LOG:Event_Data2","LOG:Event_Data3_Label","LOG:Event_Data3","LOG:Event_Data4_Label","LOG:Event_Data4","LOG:Event_Data5_Label","LOG:Event_Data5","LOG:Event_Data6_Label","LOG:Event_Data6","LOG:Event_Data7_Label","LOG:Event_Data7","LOG:Event_Data8_Label","LOG:Event_Data8","LOG:Event_Data9_Label","LOG:Event_Data9","LOG:Event_Data10_Label","LOG:Event_Data10","LOG:Event_Data11_Label","LOG:Event_Data11","LOG:Event_Data12_Label","LOG:Event_Data12","LOG:Event_Data13_Label","LOG:Event_Data13","LOG:VBin_ID","LOG:Virus_ID","LOG:Quarantine_Forward_Status","LOG:Access","LOG:SDN_Status","LOG:Compressed","LOG:Depth","LOG:Still_Infected","LOG:Def_Info","LOG:Def_Sequence_Number","LOG:Clean_Info","LOG:Delete_Info","LOG:Backup_ID","LOG:Parent","LOG:GUID","LOG:Client_Group","LOG:Address","LOG:Domain_Name","LOG:NT_Domain","LOG:MAC_Address","LOG:Version","LOG:Remote_Machine","LOG:Remote_Machine_IP","LOG:Action_1_Status","LOG:Action_2_Status","LOG:License_Feature_Name","LOG:License_Feature_Version","LOG:License_Serial_Number","LOG:License_Fulfillment_ID","LOG:License_Start_Date","LOG:License_Expiration_Date","LOG:License_LifeCycle","LOG:License_Seats_Total","LOG:License_Seats","LOG:Error_Code","LOG:License_Seats_Delta","Log:Eraser Status","LOG:Domain_GUID","LOG:Session_GUID","LOG:VBin_Session_ID","LOG:Login_Domain","LOG:Event_Data_2_1","LOG:Event_Data_2_Company_Name","LOG:Event_Data_2_Size (bytes)","LOG:Event_Data_2_Hash_Type","LOG:Event_Data_2_Hash","LOG:Event_Data_2_Product_Version","LOG:Event_Data_2_7","LOG:Event_Data_2_8","LOG:Event_Data_2_9","LOG:Event_Data_2_10","LOG:Event_Data_2_11","LOG:Event_Data_2_12","LOG:Event_Data_2_Product_Name","LOG:Event_Data_2_14","LOG:Event_Data_2_15","LOG:Event_Data_2_16","LOG:Event_Data_2_17","LOG:Eraser_Category_ID","LOG:Dynamic_Categoryset_ID","LOG:Subcategoryset_ID","LOG:Display_Name_To_Use","LOG:Reputation_Disposition","LOG:Reputation_Confidence","LOG:First_Seen","LOG:Reputation_Prevalence","LOG:Downloaded_URL","LOG:Creator_For_Dropper","LOG:CIDS_State","LOG:Behavior_Risk_Level","LOG:Detection_Type","LOG:Acknowledge_Text","LOG:VSIC_State","LOG:Scan_GUID","LOG:Scan_Duration","LOG:Scan_Start_Time","LOG:TargetApp","LOG:Scan_Command_GUID","LOG:Field113","LOG:Location","LOG:Field115","LOG:Digital_Signatures_Signer","LOG:Digital_Signatures_Issuer","LOG:Digital_Signatures_Certificate_Thumbprint","LOG:Field119","LOG:Digital_Signatures_Serial_Number","LOG:Digital_Signatures_Signing_Time","LOG:Field122","LOG:Field123","LOG:Field124","LOG:Field125","LOG:Field126"\n')

    tralog.write('"File Name","Record Length","Date and Time","Action","Severity","Direction","Protocol","Remote Host","Remote MAC","Remote Port","Local Host","Local MAC","Local Port","Application","User","User Domain","Location","Occurrences","Begin Time","End Time","Rule","Field13","Rule ID","Remote Host Name","Field24","Field25","Remote Host IPV6","Local Host IPV6","Field28","Field29","Hash:MD5","Hash:SHA256","Field32","Field33","Field34"\n')

    rawlog.write('"File Name","Recode Length","Date and Time","Remote Host","Remote Port","Local Host","Local Port","Direction","Action","Application","Rule","Packet Dump","Packet Decode","Event ID","Packet Length","Field11","Remote Host Name","Field16","Field17","Remote Host IPV6","Local Host IPV6","Rule ID"\n')

    processlog.write('"File Name","Record Length","Date And Time","Severity","Action","Test Mode","Description","API","Rule Name","IPV4 Address","IPV6 Address","Caller Process ID","Caller Process","Device Instance ID","Target","File Size","User","User Domain","Location","Event ID","Field9","Begin Time","End Time","Field15","Field16","Field21","Field22","Field26"\n')

    timeline.write('"File Name","Record Length","Date/Time1","Date/Time2","Date/Time3","Field5","LOG:Time","LOG:Event","LOG:Category","LOG:Logger","LOG:Computer","LOG:User","LOG:Virus","LOG:File","LOG:WantedAction1","LOG:WantedAction2","LOG:RealAction","LOG:Virus_Type","LOG:Flags","LOG:Description","LOG:ScanID","LOG:New_Ext","LOG:Group_ID","LOG:Event_Data1","LOG:Event_Data2_Label","LOG:Event_Data2","LOG:Event_Data3_Label","LOG:Event_Data3","LOG:Event_Data4_Label","LOG:Event_Data4","LOG:Event_Data5_Label","LOG:Event_Data5","LOG:Event_Data6_Label","LOG:Event_Data6","LOG:Event_Data7_Label","LOG:Event_Data7","LOG:Event_Data8_Label","LOG:Event_Data8","LOG:Event_Data9_Label","LOG:Event_Data9","LOG:Event_Data10_Label","LOG:Event_Data10","LOG:Event_Data11_Label","LOG:Event_Data11","LOG:Event_Data12_Label","LOG:Event_Data12","LOG:Event_Data13_Label","LOG:Event_Data13","LOG:VBin_ID","LOG:Virus_ID","LOG:Quarantine_Forward_Status","LOG:Access","LOG:SDN_Status","LOG:Compressed","LOG:Depth","LOG:Still_Infected","LOG:Def_Info","LOG:Def_Sequence_Number","LOG:Clean_Info","LOG:Delete_Info","LOG:Backup_ID","LOG:Parent","LOG:GUID","LOG:Client_Group","LOG:Address","LOG:Domain_Name","LOG:NT_Domain","LOG:MAC_Address","LOG:Version","LOG:Remote_Machine","LOG:Remote_Machine_IP","LOG:Action_1_Status","LOG:Action_2_Status","LOG:License_Feature_Name","LOG:License_Feature_Version","LOG:License_Serial_Number","LOG:License_Fulfillment_ID","LOG:License_Start_Date","LOG:License_Expiration_Date","LOG:License_LifeCycle","LOG:License_Seats_Total","LOG:License_Seats","LOG:Error_Code","LOG:License_Seats_Delta","Log:Eraser Status","LOG:Domain_GUID","LOG:Session_GUID","LOG:VBin_Session_ID","LOG:Login_Domain","LOG:Event_Data_2_1","LOG:Event_Data_2_Company_Name","LOG:Event_Data_2_Size (bytes)","LOG:Event_Data_2_Hash_Type","LOG:Event_Data_2_Hash","LOG:Event_Data_2_Product_Version","LOG:Event_Data_2_7","LOG:Event_Data_2_8","LOG:Event_Data_2_9","LOG:Event_Data_2_10","LOG:Event_Data_2_11","LOG:Event_Data_2_12","LOG:Event_Data_2_Product_Name","LOG:Event_Data_2_14","LOG:Event_Data_2_15","LOG:Event_Data_2_16","LOG:Event_Data_2_17","LOG:Eraser_Category_ID","LOG:Dynamic_Categoryset_ID","LOG:Subcategoryset_ID","LOG:Display_Name_To_Use","LOG:Reputation_Disposition","LOG:Reputation_Confidence","LOG:First_Seen","LOG:Reputation_Prevalence","LOG:Downloaded_URL","LOG:Creator_For_Dropper","LOG:CIDS_State","LOG:Behavior_Risk_Level","LOG:Detection_Type","LOG:Acknowledge_Text","LOG:VSIC_State","LOG:Scan_GUID","LOG:Scan_Duration","LOG:Scan_Start_Time","LOG:TargetApp","LOG:Scan_Command_GUID","LOG:Field113","LOG:Location","LOG:Field115","LOG:Digital_Signatures_Signer","LOG:Digital_Signatures_Issuer","LOG:Digital_Signatures_Certificate_Thumbprint","LOG:Field119","LOG:Digital_Signatures_Serial_Number","LOG:Digital_Signatures_Signing_Time","LOG:Field122","LOG:Field123","LOG:Field124","LOG:Field125","LOG:Field126"\n')

    tamperProtect.write('"File Name","Computer","User","Action Taken","Object Type","Event","Actor","Target","Target Process","Date and Time"\n')

    quarantine.write('"File Name","Description","Record ID","Modify Date 1 UTC","Creation Date 1 UTC","Access Date 1 UTC","VBin Time 1 UTC","Storage Name","Storage Instance ID","Storage Key","File Size 1","Creation Date 2 UTC","Access Date 2 UTC","Modify Date 2 UTC","VBin Time 2 UTC","Unique ID","Record Type","Quarantine Session ID","Remediation Type","Wide Description","SDDL","SHA1","Quarantine Container Size","File Size 2","Detection Digest","Virus","GUID","Additional Info","Owner SID","LOG:Time","LOG:Event","LOG:Category","LOG:Logger","LOG:Computer","LOG:User","LOG:Virus","LOG:File","LOG:WantedAction1","LOG:WantedAction2","LOG:RealAction","LOG:Virus_Type","LOG:Flags","LOG:Description","LOG:ScanID","LOG:New_Ext","LOG:Group_ID","LOG:Event_Data1","LOG:Event_Data2_Label","LOG:Event_Data2","LOG:Event_Data3_Label","LOG:Event_Data3","LOG:Event_Data4_Label","LOG:Event_Data4","LOG:Event_Data5_Label","LOG:Event_Data5","LOG:Event_Data6_Label","LOG:Event_Data6","LOG:Event_Data7_Label","LOG:Event_Data7","LOG:Event_Data8_Label","LOG:Event_Data8","LOG:Event_Data9_Label","LOG:Event_Data9","LOG:Event_Data10_Label","LOG:Event_Data10","LOG:Event_Data11_Label","LOG:Event_Data11","LOG:Event_Data12_Label","LOG:Event_Data12","LOG:Event_Data13_Label","LOG:Event_Data13","LOG:VBin_ID","LOG:Virus_ID","LOG:Quarantine_Forward_Status","LOG:Access","LOG:SDN_Status","LOG:Compressed","LOG:Depth","LOG:Still_Infected","LOG:Def_Info","LOG:Def_Sequence_Number","LOG:Clean_Info","LOG:Delete_Info","LOG:Backup_ID","LOG:Parent","LOG:GUID","LOG:Client_Group","LOG:Address","LOG:Domain_Name","LOG:NT_Domain","LOG:MAC_Address","LOG:Version","LOG:Remote_Machine","LOG:Remote_Machine_IP","LOG:Action_1_Status","LOG:Action_2_Status","LOG:License_Feature_Name","LOG:License_Feature_Version","LOG:License_Serial_Number","LOG:License_Fulfillment_ID","LOG:License_Start_Date","LOG:License_Expiration_Date","LOG:License_LifeCycle","LOG:License_Seats_Total","LOG:License_Seats","LOG:Error_Code","LOG:License_Seats_Delta","Log:Eraser Status","LOG:Domain_GUID","LOG:Session_GUID","LOG:VBin_Session_ID","LOG:Login_Domain","LOG:Event_Data_2_1","LOG:Event_Data_2_Company_Name","LOG:Event_Data_2_Size (bytes)","LOG:Event_Data_2_Hash_Type","LOG:Event_Data_2_Hash","LOG:Event_Data_2_Product_Version","LOG:Event_Data_2_7","LOG:Event_Data_2_8","LOG:Event_Data_2_9","LOG:Event_Data_2_10","LOG:Event_Data_2_11","LOG:Event_Data_2_12","LOG:Event_Data_2_Product_Name","LOG:Event_Data_2_14","LOG:Event_Data_2_15","LOG:Event_Data_2_16","LOG:Event_Data_2_17","LOG:Eraser_Category_ID","LOG:Dynamic_Categoryset_ID","LOG:Subcategoryset_ID","LOG:Display_Name_To_Use","LOG:Reputation_Disposition","LOG:Reputation_Confidence","LOG:First_Seen","LOG:Reputation_Prevalence","LOG:Downloaded_URL","LOG:Creator_For_Dropper","LOG:CIDS_State","LOG:Behavior_Risk_Level","LOG:Detection_Type","LOG:Acknowledge_Text","LOG:VSIC_State","LOG:Scan_GUID","LOG:Scan_Duration","LOG:Scan_Start_Time","LOG:TargetApp","LOG:Scan_Command_GUID","LOG:Field113","LOG:Location","LOG:Field115","LOG:Digital_Signatures_Signer","LOG:Digital_Signatures_Issuer","LOG:Digital_Signatures_Certificate_Thumbprint","LOG:Field119","LOG:Digital_Signatures_Serial_Number","LOG:Digital_Signatures_Signing_Time","LOG:Field122","LOG:Field123","LOG:Field124","LOG:Field125","LOG:Field126"\n')
    
    settings.write('"Log Name","Max Log Size","# of Logs","Running Total of Logs","Max Log Days","Field3","Field5","Field6"\n')
    
    if args.struct:
        rt0v1.write('"File Name","QFM_HEADER_Offset","Description","Log_line","Flags","Record_ID","Date_Created","Date_Accessed","Date_Modified","Data_Type1","Unknown1","Storage_Name","Storage_Instance_ID","Storage_Key","Data_Type2","Unknown2","Unknown3","Data_Type3","Quarantine_File_Size","Date_Accessed_2","Date_Modified_2","Date_Created_2","VBin_Time_2","Unknown4","Unique_ID","Unknown5","Unknown6","Record_Type","Quarantine_Session_ID","Remediation_Type","Unknown7","Unknown8","Unknown9","Unknown10","Unknown11","Unknown12","Unknown13","WDescription","Unknown14","QData_Location_Header","QData_Location_Offset","QData_Location_Size","EOF","Unknown15","QData_Info_Header","QData_Info_Size","Data"\n')
        
        rt0v2.write('"File Name","QFM_HEADER_Offset","Description","Log_line","Flags","Record_ID","Date_Created","Date_Accessed","Date_Modified","Data_Type1","Unknown1","Storage_Name","Storage_Instance_ID","Storage_Key","Data_Type2","Unknown2","Unknown3","Data_Type3","Quarantine_File_Size","Date_Accessed_2","Date_Modified_2","Date_Created_2","VBin_Time_2","Unknown4","Unique_ID","Unknown5","Unknown6","Record_Type","Quarantine_Session_ID","Remediation_Type","Unknown7","Unknown8","Unknown9","Unknown10","Unknown11","Unknown12","Unknown13","WDescription","Unknown14","QData_Location_Header","QData_Location_Offset","QData_Location_Size","EOF","Unknown15","QData_Info_Header","QData_Info_Size","Data"\n')
        
        rt1v1.write('"File Name","QFM_HEADER_Offset","Description","Log_line","Flags","Record_ID","Date_Created","Date_Accessed","Date_Modified","Data_Type1","Unknown1","Storage_Name","Storage_Instance_ID","Storage_Key","Data_Type2","Unknown2","Unknown3","Data_Type3","Quarantine_File_Size","Date_Accessed_2","Date_Modified_2","Date_Created_2","VBin_Time_2","Unknown4","Unique_ID","Unknown5","Unknown6","Record_Type","Quarantine_Session_ID","Remediation_Type","Unknown7","Unknown8","Unknown9","Unknown10","Unknown11","Unknown12","Unknown13","WDescription","Unknown14"\n')
        
        rt1v2.write('"File Name","QFM_HEADER_Offset","Description","Log_line","Flags","Record_ID","Date_Created","Date_Accessed","Date_Modified","Data_Type1","Unknown1","Storage_Name","Storage_Instance_ID","Storage_Key","Data_Type2","Unknown2","Unknown3","Data_Type3","Quarantine_File_Size","Date_Accessed_2","Date_Modified_2","Date_Created_2","VBin_Time_2","Unknown4","Unique_ID","Unknown5","Unknown6","Record_Type","Quarantine_Session_ID","Remediation_Type","Unknown7","Unknown8","Unknown9","Unknown10","Unknown11","Unknown12","Unknown13","WDescription","Unknown14"\n')
        
        rt2v1.write('"File Name","QFM_HEADER_Offset","Description","Log_line","Flags","Record_ID","Date_Created","Date_Accessed","Date_Modified","Data_Type1","Unknown1","Storage_Name","Storage_Instance_ID","Storage_Key","Data_Type2","Unknown2","Unknown3","Data_Type3","Quarantine_File_Size","Date_Accessed_2","Date_Modified_2","Date_Created_2","VBin_Time_2","Unknown4","Unique_ID","Unknown5","Unknown6","Record_Type","Quarantine_Session_ID","Remediation_Type","Unknown7","Unknown8","Unknown9","Unknown10","Unknown11","Unknown12","Unknown13","WDescription","Unknown14","QFM_Header","QFM_Header_Size","QFM_Size","QFM_Size_Header_Size","Data_Size_From_End_of_QFM-to_End_of_VBN","Tag1","Tag1_Data","Tag2","Tag2_Data","Tag3","Hash_Size","SHA1","Tag4","Tag4_Data","Tag5","Tag5_Data","Tag6","QFS_Size","Quarantine_File_Info_Size","Tag7","Security_Descriptor_Size","Security_Descriptor","Tag8","Tag8_Data","Tag9","Quarantine_File_Info_Size_2","Unknown15","Size","Unknown16","Unknown17","File_Size","Unknown18","Unknown19","Size2","Unknown20","Unknown21"\n')
        
        rt2v2.write('"File Name","QFM_HEADER_Offset","Description","Log_line","Flags","Record_ID","Date_Created","Date_Accessed","Date_Modified","Data_Type1","Unknown1","Storage_Name","Storage_Instance_ID","Storage_Key","Data_Type2","Unknown2","Unknown3","Data_Type3","Quarantine_File_Size","Date_Accessed_2","Date_Modified_2","Date_Created_2","VBin_Time_2","Unknown4","Unique_ID","Unknown5","Unknown6","Record_Type","Quarantine_Session_ID","Remediation_Type","Unknown7","Unknown8","Unknown9","Unknown10","Unknown11","Unknown12","Unknown13","WDescription","Unknown14","QFM_Header","QFM_Header_Size","QFM_Size","QFM_Size_Header_Size","Data_Size_From_End_of_QFM-to_End_of_VBN","Tag1","Tag1_Data","Tag2","Tag2_Data","Tag3","Hash_Size","SHA1","Tag4","Tag4_Data","Tag5","Tag5_Data","Tag6","QFS_Size","Quarantine_File_Info_Size","Tag7","Security_Descriptor_Size","Security_Descriptor","Tag8","Tag8_Data","Tag9","Quarantine_File_Info_Size_2","Unknown15","Size","Unknown16","Unknown17","File_Size","Unknown18","Unknown19","Size2","Unknown20","Unknown21"\n')

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
    location = ''
    urlhidlevel = ''
    urlriskscore = ''
    urlcategories = ''

VBN_DEF = """

typedef struct _VBN_METADATA_V1{
    int32 QFM_HEADER_Offset;
    char Description[384];
    char Log_line[984];
    int32 Flags; //if 0x2 contains dates, if 0x1 no dates
    uint32 Record_ID;
    int64 Date_Created;
    int64 Date_Accessed;
    int64 Date_Modified;
    int32 Data_Type1; //if 0x2 contains storage info, if 0x0 no storage info
    char Unknown1[484];
    char Storage_Name[48];
    int32 Storage_Instance_ID;
    char Storage_Key[384];
    int32 Data_Type2;
    int32 Unknown2;
    char Unknown3[8];
    int32 Data_Type3;
    int32 Quarantine_File_Size;
    int32 Date_Accessed_2;
    int32 Date_Modified_2;
    int32 Date_Created_2;
    int32 VBin_Time_2;
    char Unknown4[8];
    char Unique_ID[16];
    char Unknown5[260];
    int32 Unknown6;
    int32 Record_Type; 
    int32 Quarantine_Session_ID;
    int32 Remediation_Type;
    int32 Unknown7;
    int32 Unknown8;
    int32 Unknown9;
    int32 Unknown10;
    int32 Unknown11;
    int32 Unknown12;
    int32 Unknown13;
    wchar WDescription[384];
    char Unknown14[212];
} VBN_METADATA_V1;

typedef struct _VBN_METADATA_V2 {
    int32 QFM_HEADER_Offset;
    char Description[384];
    char Log_line[2048];
    int32 Flags; //if 0x2 contains dates, if 0x1 no dates
    uint32 Record_ID;
    int64 Date_Created;
    int64 Date_Accessed;
    int64 Date_Modified;
    int32 Data_Type1; //if 0x2 contains storage info, if 0x0 no storage info
    char Unknown1[484];
    char Storage_Name[48];
    int32 Storage_Instance_ID;
    char Storage_Key[384];
    int32 Data_Type2;
    uint32 Unknown2;
    char Unknown3[8];
    int32 Data_Type3;
    int32 Quarantine_File_Size;
    int64 Date_Accessed_2;
    int64 Date_Modified_2;
    int64 Date_Created_2;
    int64 VBin_Time_2;
    char Unknown4[4];
    char Unique_ID[16];
    char Unknown5[260];
    int32 Unknown6;
    int32 Record_Type; 
    uint32 Quarantine_Session_ID;
    int32 Remediation_Type;
    int32 Unknown7;
    int32 Unknown8;
    int32 Unknown9;
    int32 Unknown10;
    int32 Unknown11;
    int32 Unknown12;
    int32 Unknown13;
    wchar WDescription[384];
    char Unknown14[212];
} VBN_METADATA_V2;

typedef struct _VBN_METADATA_Linux{
    int32 QFM_HEADER_Offset;
    char Description[4096];
    char Log_line[1112];
    int32 Flags; //if 0x2 contains dates, if 0x1 no dates
    uint32 Record_ID;
    char Unknown1[40];
    int32 Date_Modified;
    int32 Date_Created;
    int32 Date_Accessed;
    int32 VBin_Time;
    int32 Data_Type1; //if 0x2 contains storage info, if 0x0 no storage info
    char Unknown2[452];
    char Storage_Name[48];
    int32 Storage_Instance_ID;
    char Storage_Key[4096];
    int32 Data_Type2;
    int32 Unknown3;
    char Unknown4[44];
    int32 Data_Type3;
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
    int32 Unknown8;
    int32 Unknown9;
    int32 Unknown10;
    int32 Unknown11;
    int32 Unknown12;
    int32 Unknown13;
    int32 Unknown14;
    wchar WDescription[384];
    char Unknown15[212];
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
    byte Value;
} ASN1_1;

typedef struct _ASN1_2 {
    byte Tag;
    short Value;
} ASN1_2;

typedef struct _ASN1_3 {
    byte Tag;
    char Value[3];
} ASN1_3;

typedef struct _ASN1_4 {
    byte Tag;
    long Value;
} ASN1_4;

typedef struct _ASN1_8 {
    byte Tag;
    char Value[8];
} ASN1_8;

typedef struct _ASN1_16 {
    byte Tag;
    char GUID[16];
} ASN1_16;

typedef struct _ASN1_String_A {
    byte Tag;
    int32 Data_Length;
    char StringA[Data_Length];
} ASN1_String_A;

typedef struct _ASN1_String_W {
    byte Tag;
    int32 Data_Length;
    char StringW[Data_Length];
} ASN1_String_W;

typedef struct _ASN1_GUID {
    byte Tag;
    int32 Data_Length;
    char GUID[Data_Length];
} ASN1_GUID;

typedef struct _ASN1_BLOB {
    byte Tag;
    int32 Data_Length;
    char BLOB[Data_Length];
} ASN1_BLOB;

typedef struct _ASN1_Error {
    char Data[16];
} ASN1_Error;

typedef struct _Quarantine_File_Info {
    byte Tag1;
    int32 Tag1_Data;
    byte Tag2;
    byte Tag2_Data;
} Quarantine_File_Info;

typedef struct _Quarantine_File_Info2 {
    byte Tag3;
} Quarantine_File_Info2;

typedef struct _Quarantine_File_Info3 {
    byte Tag3
    int32 Hash_Size;
    char SHA1[Hash_Size]; //need to fix for wchar
    byte Tag4;
    int32 Tag4_Data;
    byte Tag5;
    int32 Tag5_Data;
    byte Tag6;
    int32 QFS_Size;
    char Quarantine_File_Info_Size[QFS_Size];
} Quarantine_File_Info3;

typedef struct _Quarantine_File_Info4 {
    byte Tag7;
    int32 Security_Descriptor_Size;
    char Security_Descriptor[Security_Descriptor_Size]; //need to fix for wchar
    byte Tag8;
    int32 Tag8_Data;
    byte Tag9;
    int64 Quarantine_File_Info_Size_2;
} Quarantine_File_Info4;

typedef struct _Chunk {
    byte Data_Type;
    int32 Chunk_Size;
} Chunk;

typedef struct _Junk_Header {
    int64 Unknown15;
    int64 Size;
    char Unknown16[Size];
    char Unknown17[12];
    int32 File_Size;
    int64 Unknown18;
} Junk_Header;

typedef struct _Junk_Footer {
    int64 Data_Type;
    int64 Data_Size;
    int32 ADS_Name_Size;
    char ADS_Name[ADS_Name_Size];
    char Data[Data_Size];
} Junk_Footer;

typedef struct _QData_Location {
    int64 Header;
    int64 QData_Location_Offset;
    int64 QData_Location_Size;
    int32 EOF;
    char Unknown15[QData_Location_Offset -28];
} QData_Location;

typedef struct _QData_Info {
    int64 QData_Info_Header;
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
                   #Compliance events:
                   '209':'Host Integrity failed (TSLOG_SEC_NO_AV)',
                   '210':'Host Integrity passed (TSLOG_SEC_AV)',
                   '221':'Host Integrity failed but it was reported as PASS',
                   '237':'Host Integrity custom log entry',
                   #Firewall and IPS events:
                   '201':'Invalid traffic by rule', #SEP14.2.1
                   '202':'Port Scan', #SEP14.2.1
                   '203':'Denial-of-service attack', #SEP14.2.1
                   '204':'Trojan horse', #SEP14.2.1
                   '205':'Executable file changed', #SEP14.2.1
                   '206':'Intrusion Prevention System (Intrusion Detected,TSLOG_SEC_INTRUSION_DETECTED)', #SEP14.2.1
                   '207':'Active Response',
                   '208':'MAC Spoofing', #SEP14.2.1
                   '211':'Active Response Disengaged',
                   '216':'Executable file change detected',
                   '217':'Executable file change accepted',
                   '218':'Executable file change denied',
                   '219':'Active Response Canceled', #SEP14.2.1
                   '220':'Application Hijacking',
                   '249':'Browser Protection event',
                   #Application and Device control:
                   '238':'Device control disabled device',
                   '239':'Buffer Overflow Event',
                   '240':'Software protection has thrown an exception',
                   '241':'Not used', #SEP14.2.1
                   '242':'Device control enabled the device', #SEP14.2.1
                   #Memory Exploit Mitigation events:
                   '250':'Memory Exploit Mitigation blocked an event', #SEP14.2.1
                   '251':'Memory Exploit Mitigation allowed an event' #SEP14.2.1
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
        if data[3].decode("utf-8", "ignore") == '2' and data[64].decode("utf-8", "ignore") == '1':
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

def log_quarantine_forward_status(_):
    status = {
              '0':'None',
              '1':'Failed',
              '2':'OK'
             }

    for k, v in status.items():
        if k == _:
            return v

    else:
        return _

def log_yn(_):
    yn = {
          '0':'No',
          '1':'Yes'
         }
    
    for k, v in yn.items():
        if k == _:
            return v

    else:
        return _

def log_clean_info(_):
    clean = {
             '0':'Cleanable',
             '1':'No Clean Pattern',
             '2':'Not Cleanable'
            }
    
    for k, v in clean.items():
        if k == _:
            return v

    else:
        return _

def log_delete_info(_):
    delete = {
              '4':'Deletable',
              '5':'Not Deletable'
             }
    
    for k, v in delete.items():
        if k == _:
            return v

    else:
        return _

def log_eraser_status(_):
    status = {
              '0':'Success',
              '1':'Reboot Required',
              '2':'Nothing To Do',
              '3':'Repaired',
              '4':'Deleted',
              '5':'False',
              '6':'Abort',
              '7':'Continue',
              '8':'Service Not Stopped',
              '9':'Application Heuristic Scan Failure',
              '10':'Cannot Remediate',
              '11':'Whitelist Failure',
              '12':'Driver Failure',
              '13':'Reserved01',
              '13':'Commercial Application List Failure',
              '13':'Application Heuristic Scan Invalid OS',
              '13':'Content Manager Data Error',
              '999':'Leave Alone',
              '1000':'Generic Failure',
              '1001':'Out Of Memory',
              '1002':'Not Initialized',
              '1003':'Invalid Argument',
              '1004':'Insufficient Buffer',
              '1005':'Decryption Error',
              '1006':'File Not Found',
              '1007':'Out Of Range',
              '1008':'COM Error',
              '1009':'Partial Failure',
              '1010':'Bad Definitions',
              '1011':'Invalid Command',
              '1012':'No Interface',
              '1013':'RSA Error',
              '1014':'Path Not Empty',
              '1015':'Invalid Path',
              '1016':'Path Not Empty',
              '1017':'File Still Present',
              '1018':'Invalid OS',
              '1019':'Not Implemented',
              '1020':'Access Denied',
              '1021':'Directory Still Present',
              '1022':'Inconsistent State',
              '1023':'Timeout',
              '1024':'Action Pending',
              '1025':'Volume Write Protected',
              '1026':'Not Reparse Point',
              '1027':'File Exists',
              '1028':'Target Protected',
              '1029':'Disk Full',
              '1030':'Shutdown In Progress',
              '1031':'Media Error',
              '1032':'Network Defs Error'
              }

    for k, v in status.items():
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
                 '1':'File","Create',
                 '2':'File","Delete',
                 '3':'File","Open',
                 '6':'Directory","Create',
                 '7':'Directory","Delete',
                 '14':'Registry Key","Create',
                 '15':'Registry Key","Delete',
                 '16':'Registry Value","Delete',
                 '17':'Registry Value","Set',
                 '18':'Registry Key","Rename',
                 '19':'Registry Key","Set Security',
                 '45':'File","Set Security',
                 '46':'Directory","Set Security',
                 '55':'Process","Open',
                 '56':'Process","Duplicate'
                }

        for k, v in event.items():
            if k == _:
                return v

    return str('","'+_)

def protocol(_):
    protocol = {
                '301':'TCP',
                '302':'UDP',
                '303':'Ping',
                '304':'TCP',
                '305':'Other',
                '306':'ICMP',
                '307':'ETHERNET',
                '308':'IP'
                }

    for k, v in protocol.items():
        if k == str(_):
            return v

    else:
        return _
        
def eth_type(_):
    type = {
            range(257, 512):'Experimental',
            512:'XEROX PUP (see 0A00)',
            513:'PUP Addr Trans (see 0A01)',
            1024:'Nixdorf',
            1536:'XEROX NS IDP',
            1632:'DLOG',
            1633:'DLOG',
            2048:'Internet Protocol version 4 (IPv4)',
            2049:'X.75 Internet',
            2050:'NBS Internet',
            2051:'ECMA Internet',
            2052:'Chaosnet',
            2053:'X.25 Level 3',
            2054:'Address Resolution Protocol (ARP)',
            2055:'XNS Compatability',
            2056:'Frame Relay ARP',
            2076:'Symbolics Private',
            range(2184, 2187):'Xyplex',
            2304:'Ungermann-Bass net debugr',
            2560:'Xerox IEEE802.3 PUP',
            2561:'PUP Addr Trans',
            2989:'Banyan VINES',
            2990:'VINES Loopback',
            2991:'VINES Echo',
            4096:'Berkeley Trailer nego',
            range(4097, 4112):'Berkeley Trailer encap/IP',
            5632:'Valid Systems',
            8947:'TRILL',
            8948:'L2-IS-IS',
            16962:'PCS Basic Block Protocol',
            21000:'BBN Simnet',
            24576:'DEC Unassigned (Exp.)',
            24577:'DEC MOP Dump/Load',
            24578:'DEC MOP Remote Console',
            24579:'DEC DECNET Phase IV Route',
            24580:'DEC LAT',
            24581:'DEC Diagnostic Protocol',
            24582:'DEC Customer Protocol',
            24583:'DEC LAVC; SCA',
            range(24584, 24586):'DEC Unassigned',
            range(24592, 24597):'3Com Corporation',
            25944:'Trans Ether Bridging',
            25945:'Raw Frame Relay',
            28672:'Ungermann-Bass download',
            28674:'Ungermann-Bass dia/loop',
            range(28704, 28714):'LRT',
            28720:'Proteon',
            28724:'Cabletron',
            32771:'Cronus VLN',
            32772:'Cronus Direct',
            32773:'HP Probe',
            32774:'Nestar',
            32776:'AT&T',
            32784:'Excelan',
            32787:'SGI diagnostics',
            32788:'SGI network games',
            32789:'SGI reserved',
            32790:'SGI bounce server',
            32793:'Apollo Domain',
            32814:'Tymshare',
            32815:'Tigan; Inc.',
            32821:'Reverse Address Resolution Protocol (RARP)',
            32822:'Aeonic Systems',
            32824:'DEC LANBridge',
            range(32825, 32829):'DEC Unassigned',
            32829:'DEC Ethernet Encryption',
            32830:'DEC Unassigned',
            32831:'DEC LAN Traffic Monitor',
            range(32832, 32835):'DEC Unassigned',
            32836:'Planning Research Corp.',
            32838:'AT&T',
            32839:'AT&T',
            32841:'ExperData',
            32859:'Stanford V Kernel exp.',
            32860:'Stanford V Kernel prod.',
            32861:'Evans & Sutherland',
            32864:'Little Machines',
            32866:'Counterpoint Computers',
            32869:'Univ. of Mass. @ Amherst',
            32870:'Univ. of Mass. @ Amherst',
            32871:'Veeco Integrated Auto.',
            32872:'General Dynamics',
            32873:'AT&T',
            32874:'Autophon',
            32876:'ComDesign',
            32877:'Computgraphic Corp.',
            range(32878, 32888):'Landmark Graphics Corp.',
            32890:'Matra',
            32891:'Dansk Data Elektronik',
            32892:'Merit Internodal',
            range(32893, 32896):'Vitalink Communications',
            32896:'Vitalink TransLAN III',
            range(32897, 32900):'Counterpoint Computers',
            32923:'Appletalk',
            range(32924, 32927):'Datability',
            32927:'Spider Systems Ltd.',
            32931:'Nixdorf Computers',
            range(32932, 32948):'Siemens Gammasonics Inc.',
            range(32960, 32964):'DCA Data Exchange Cluster',
            32964:'Banyan Systems',
            32965:'Banyan Systems',
            32966:'Pacer Software',
            32967:'Applitek Corporation',
            range(32968, 32973):'Intergraph Corporation',
            range(32973, 32975):'Harris Corporation',
            range(32975, 32979):'Taylor Instrument',
            range(32979, 32981):'Rosemount Corporation',
            32981:'IBM SNA Service on Ether',
            32989:'Varian Associates',
            range(32990, 32992):'Integrated Solutions TRFS',
            range(128, 524289):'Allen-Bradley',
            range(8388608, 33009):'Datability',
            33010:'Retix',
            33011:'AppleTalk AARP (Kinetics)',
            range(33012, 33014):'Kinetics',
            33015:'Apollo Computer',
            33023:'Wellfleet Communications',
            33024:'Customer VLAN Tag Type (C-Tag; formerly called the Q-Tag) (initially Wellfleet)',
            range(33025, 33028):'Wellfleet Communications',
            range(33031, 33034):'Symbolics Private',
            33072:'Hayes Microcomputers',
            33073:'VG Laboratory Systems',
            range(33074, 33079):'Bridge Communications',
            range(33079, 33081):'Novell; Inc.',
            range(33081, 33086):'KTI',
            33096:'Logicraft',
            33097:'Network Computing Devices',
            33098:'Alpha Micro',
            33100:'SNMP',
            33101:'BIIN',
            33102:'BIIN',
            33103:'Technically Elite Concept',
            33104:'Rational Corp',
            range(33105, 33108):'Qualcomm',
            range(33116, 33119):'Computer Protocol Pty Ltd',
            range(33124, 33127):'Charles River Data System',
            33149:'XTP',
            33150:'SGI/Time Warner prop.',
            33152:'HIPPI-FP encapsulation',
            33153:'STP; HIPPI-ST',
            33154:'Reserved for HIPPI-6400',
            33155:'Reserved for HIPPI-6400',
            range(33156, 33165):'Silicon Graphics prop.',
            33165:'Motorola Computer',
            range(33178, 33188):'Qualcomm',
            33188:'ARAI Bunkichi',
            range(33189, 33199):'RAD Network Devices',
            range(33207, 33210):'Xyplex',
            range(33228, 33238):'Apricot Computers',
            range(33238, 33246):'Artisoft',
            range(33254, 33264):'Polygon',
            range(33264, 33267):'Comsat Labs',
            range(33267, 33270):'SAIC',
            range(33270, 33273):'VG Analytical',
            range(33283, 33286):'Quantum Software',
            range(33313, 33315):'Ascom Banking Systems',
            range(33342, 33345):'Advanced Encryption Syste',
            range(33407, 33411):'Athena Programming',
            range(33379, 33387):'Charles River Data System',
            range(33434, 33436):'Inst Ind Info Tech',
            range(33436, 33452):'Taurus Controls',
            range(33452, 34452):'Walker Richer & Quinn',
            range(34452, 34462):'Idea Courier',
            range(34462, 34466):'Computer Network Tech',
            range(34467, 34477):'Gateway Communications',
            34523:'SECTRA',
            34526:'Delta Controls',
            34525:'Internet Protocol version 6 (IPv6)',
            34527:'ATOMIC',
            range(34528, 34544):'Landis & Gyr Powers',
            range(34560, 34577):'Motorola',
            34667:'TCP/IP Compression',
            34668:'IP Autonomous Systems',
            34669:'Secure Data',
            34824:'IEEE Std 802.3 - Ethernet Passive Optical Network (EPON)',
            34827:'Point-to-Point Protocol (PPP)',
            34828:'General Switch Management Protocol (GSMP)',
            34887:'MPLS',
            34888:'MPLS with upstream-assigned label',
            34913:'Multicast Channel Allocation Protocol (MCAP)',
            34915:'PPP over Ethernet (PPPoE) Discovery Stage',
            34916:'PPP over Ethernet (PPPoE) Session Stage',
            34958:'IEEE Std 802.1X - Port-based network access control',
            34984:'IEEE Std 802.1Q - Service VLAN tag identifier (S-Tag)',
            range(35478, 35480):'Invisible Software',
            34997:'IEEE Std 802 - Local Experimental Ethertype',
            34998:'IEEE Std 802 - Local Experimental Ethertype',
            34999:'IEEE Std 802 - OUI Extended Ethertype',
            35015:'IEEE Std 802.11 - Pre-Authentication (802.11i)',
            35020:'IEEE Std 802.1AB - Link Layer Discovery Protocol (LLDP)',
            35045:'IEEE Std 802.1AE - Media Access Control Security',
            35047:'Provider Backbone Bridging Instance tag',
            35061:'IEEE Std 802.1Q  - Multiple VLAN Registration Protocol (MVRP)',
            35062:'IEEE Std 802.1Q - Multiple Multicast Registration Protocol (MMRP)',
            35085:'IEEE Std 802.11 - Fast Roaming Remote Request (802.11r)',
            35095:'IEEE Std 802.21 - Media Independent Handover Protocol',
            35113:'IEEE Std 802.1Qbe - Multiple I-SID Registration Protocol',
            35131:'TRILL Fine Grained Labeling (FGL)',
            35136:'IEEE Std 802.1Qbg - ECP Protocol (also used in 802.1BR)',
            35142:'TRILL RBridge Channel',
            35143:'GeoNetworking as defined in ETSI EN 302 636-4-1',
            35151:'NSH (Network Service Header)',
            36864:'Loopback',
            36865:'3Com(Bridge) XNS Sys Mgmt',
            36866:'3Com(Bridge) TCP-IP Sys',
            36867:'3Com(Bridge) loop detect',
            39458:'Multi-Topology',
            41197:'LoWPAN encapsulation',
            47082:'The Ethertype will be used to identify a Channel in which control messages are encapsulated as payload of GRE packets. When a GRE packet tagged with the Ethertype is received; the payload will be handed to the network processor for processing.',
            65280:'BBN VITAL-LanBridge cache',
            range(65280, 65296):'ISC Bunker Ramo',
            65535:'Reserved'
            }

    for k,v in type.items():
        if k == _:
            return v

    return _

def icmp_type_code(type, code):
    typeName = ''
    codeDescription = ''
    types = {
             0: {
                 'type':'Echo Reply',
                 0:'No Code'
                },
             1: {
                 'type':'Unassigned'
                },
             2: {
                 'type':'Unassigned'
                },
             3: {
                 'type':'Destination Unreachable',
                 0:'Net Unreachable',
                 1:'Host Unreachable',
                 2:'Protocol Unreachable',
                 3:'Port Unreachable',
                 4:'Fragmentation Needed and Do not Fragment was Set',
                 5:'Source Route Failed',
                 6:'Destination Network Unknown',
                 7:'Destination Host Unknown',
                 8:'Source Host Isolated',
                 9:'Communication with Destination Network is Administratively Prohibited',
                 10:'Communication with Destination Host is Administratively Prohibited',
                 11:'Destination Network Unreachable for Type of Service',
                 12:'Destination Host Unreachable for Type of Service',
                 13:'Communication Administratively Prohibited',
                 14:'Host Precedence Violation',
                 15:'Precedence cutoff in effect'
                },
             4: {
                 'type':'Source Quench (Deprecated)',
                 0:'No Code'
                },
             5: {
                 'type':'Redirect',
                 0:'Redirect Datagram for the Network (or subnet)',
                 1:'Redirect Datagram for the Host',
                 2:'Redirect Datagram for the Type of Service and Network',
                 3:'Redirect Datagram for the Type of Service and Host'
                },
             6: {
                 'type':'Alternate Host Address (Deprecated)',
                 0:'Alternate Address for Host'
                },
             7: {
                 'type':'Unassigned'
                },
             8: {
                 'type':'Echo',
                 0:'No Code'
                },
             9: {
                 'type':'Router Advertisement',
                 0:'Normal router advertisement',
                 16:'Does not route common traffic'
                },
             10: {
                 'type':'Router Solicitation',
                 0:'No Code'
                },
             11: {
                 'type':'Time Exceeded',
                 0:'Time to Live exceeded in Transit',
                 1:'Fragment Reassembly Time Exceeded'
                },
             12: {
                 'type':'Parameter Problem',
                 0:'Pointer indicates the error',
                 1:'Missing a Required Option',
                 2:'Bad Length'
                },
             13: {
                 'type':'Timestamp',
                 0:'No Code'
                },
             14: {
                 'type':'Timestamp Reply',
                 0:'No Code'
                },
             15: {
                 'type':'Information Request (Deprecated)',
                 0:'No Code'
                },
             16: {
                 'type':'Information Reply (Deprecated)',
                 0:'No Code'
                },
             17: {
                 'type':'Address Mask Request (Deprecated)',
                 0:'No Code'
                },
             18: {
                 'type':'Address Mask Reply (Deprecated)',
                 0:'No Code'
                },
             19: {
                 'type':'Reserved (for Security)'
                },
             range(20, 30): {
                 'type':'Reserved (for Robustness Experiment)'
                },
             30: {
                 'type':'Traceroute (Deprecated)'
                },
             31: {
                 'type':'Datagram Conversion Error (Deprecated)'
                },
             32: {
                 'type':'Mobile Host Redirect (Deprecated)'
                },
             33: {
                 'type':'IPv6 Where-Are-You (Deprecated)'
                },
             34: {
                 'type':'IPv6 I-Am-Here (Deprecated)'
                },
             35: {
                 'type':'Mobile Registration Request (Deprecated)'
                },
             36: {
                 'type':'Mobile Registration Reply (Deprecated)'
                },
             37: {
                 'type':'Domain Name Request (Deprecated)'
                },
             38: {
                 'type':'Domain Name Reply (Deprecated))'
                },
             39: {
                 'type':'SKIP (Deprecated)'
                },
             40: {
                 'type':'Photuris',
                 0:'Bad SPI',
                 1:'Authentication Failed',
                 2:'Decompression Failed',
                 3:'Decryption Failed',
                 4:'Need Authentication',
                 5:'Need Authorization'
                },
             41: {
                 'type':'ICMP messages utilized by experimental mobility protocols such as Seamoby'
                },
             42: {
                 'type':'Extended Echo Request',
                 0:'No Error',
                 range(1, 256):'Unassigned'
                },
             43: {
                 'type':'Extended Echo Reply',
                 0:'No Error',
                 1:'Malformed Query',
                 2:'No Such Interface',
                 3:'No Such Table Entry',
                 4:'Multiple Interfaces Satisfy Query',
                 range(5, 256):'Unassigned'
                },
             range(44, 253): {
                 'type':'Unassigned'
                },
             253: {
                 'type':'RFC3692-style Experiment 1'
                },
             254: {
                 'type':'RFC3692-style Experiment 2'
                },
             255: {
                 'type':'Reserved'
                }
            }

    for k, v in types.items():
        if k == type:
            typeName = types[type]['type']
            
    for k, v in types[type].items():
        if k == code:
            codeDescription = types[type][code]
            
    return typeName, codeDescription
    
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

def read_submission(_, fname):
    test = {}
    column = 0
    for x in _.split('\n'):
        x = re.split('(?<!.{48}):(?!\\\)|(?<!.{48})=',x, maxsplit=1)
        if x[0] == 'Detection Digest':
            y = x
            column = 2
        if column == 2:
            if len(x[0]) == 0:
                x = y
                x[1] = x[1].replace('"', '""')
                column = 0
            if len(x) == 1:
                y[1] = y[1] + x[0] + '\n'
                continue
        if len(x[0]) == 0:
            continue
        if len(x) == 1:
            if re.match('[a-fA-F\d]{32}', x[0]):
                x.insert(0, 'MD5')
                
            elif re.match('Detection of', x[0]):
                x.insert(0, 'Detection')
                
            elif re.search('Submission of', x[0]):
                x.insert(0, 'Submission')

            elif re.match('BASH-', x[0]):
                x.insert(0, 'BASH Plugin')
                column = 1
                
            elif column == 1:
                x.insert(0, 'ImagePath')
                column = 0
                
            else:
                x.insert(0, 'Unknown')

        test[x[0]] = x[1]

    if 'Submission' in test:
        if args.output:
            subtype = args.output+'/ccSubSDK/SubmissionsEim.csv'
        else:
            subtype = 'ccSubSDK/SubmissionsEim.csv'
    elif 'Signature Set Version' in test:
        if args.output:
            subtype = args.output+'/ccSubSDK/IDSxp.csv'
        else:
            subtype = 'ccSubSDK/IDSxp.csv'
    elif 'BASH Plugin' in test:
        if args.output:
            subtype = args.output+'/ccSubSDK/BHSvcPlg.csv'
        else:
            subtype = 'ccSubSDK/BHSvcPlg.csv'
    else:
        if args.output:
            subtype = args.output+'/ccSubSDK/Reports.csv'
        else:
            subtype = 'ccSubSDK/Reports.csv'
    header = []
    data = ['']
    if os.path.isfile(subtype):
        data = open(subtype).readlines()
        header = data[0][1:-2].split('","')
        header.remove('ccSubSDK File GUID')
    subtype = open(subtype, 'w')
    rows = ''
    value = []
    for k, v in test.items():
        if k not in header:
            header.append(k)
        if len(header) > len(value):
            diff = len(header) - len(value)
            value += ' ' * diff
        pos = header.index(k)
        if k == 'Network Data' or k == 'Attack Data':
            value[pos] = hexdump_tag(zlib.decompress(bytearray.fromhex(v[17:]))).replace('"', '""')
        else:
            value[pos] = v
    if len(value) != 0:
        value = '","'.join(value)
        rows += f'"{fname}","{value}"\n'
    header = '","'.join(header)
    data[0] = f'"ccSubSDK File GUID","{header}"\n'
    subtype.writelines(data)
    subtype.write(rows)
    subtype.close()
    
def read_log_data(data, tz):
    entry = LogFields()
    data = re.split(b',(?=(?:[^\"]*\"[^\"]*\")*[^\"]*$)', data)
    field113 = ''
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
    entry.quarantineforwardstatus = log_quarantine_forward_status(data[20].decode("utf-8", "ignore"))
    entry.access = data[21].decode("utf-8", "ignore")
    entry.sdnstatus = data[22].decode("utf-8", "ignore")
    entry.compressed = log_yn(data[23].decode("utf-8", "ignore"))
    entry.depth = data[24].decode("utf-8", "ignore")
    entry.stillinfected = log_yn(data[25].decode("utf-8", "ignore"))
    entry.definfo = data[26].decode("utf-8", "ignore")
    entry.defsequincenumber = data[27].decode("utf-8", "ignore")
    entry.cleaninfo = log_clean_info(data[28].decode("utf-8", "ignore"))
    entry.deleteinfo = log_delete_info(data[29].decode("utf-8", "ignore"))
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
    entry.status = log_eraser_status(data[54].decode("utf-8", "ignore"))
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
        entry.location = data[81].decode("utf-8", "ignore")
        field115 = data[82].decode("utf-8", "ignore")
        entry.digitalsigner = data[83].decode("utf-8", "ignore").replace('"', '')
        entry.digitalissuer = data[84].decode("utf-8", "ignore")
        entry.digitalthumbprint = data[85].decode("utf-8", "ignore")
        field119 = data[86].decode("utf-8", "ignore")
        entry.digitalsn = data[87].decode("utf-8", "ignore")
        entry.digitaltime = from_unix_sec(data[88].decode("utf-8", "ignore"))
        field122 = data[89].decode("utf-8", "ignore")
        field123 = data[90].decode("utf-8", "ignore")
        if re.match('^([A-Za-z0-9+/]{4})*([A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{2}==)?', data[91].decode("utf-8", "ignore")):
            try:
                parsed = json.loads(base64.b64decode(data[91]).decode("utf-8", "ignore"))
                field124 = json.dumps(parsed, indent=4, sort_keys=True)
                field124 = field124.replace('"', '""')
            except:
                field124 = data[91].decode("utf-8", "ignore")
        else:
            field124 = data[91].decode("utf-8", "ignore")
        field125 = data[92].decode("utf-8", "ignore")
        field126 = data[93].decode("utf-8", "ignore")
    except:
        pass
    
    return f'"{entry.time}","{entry.event}","{entry.category}","{entry.logger}","{entry.computer}","{entry.user}","{entry.virus}","{entry.file}","{entry.wantedaction1}","{entry.wantedaction2}","{entry.realaction}","{entry.virustype}","{entry.flags}","{entry.description}","{entry.scanid}","{entry.newext}","{entry.groupid}","{entry.eventdata}","{entry.vbinid}","{entry.virusid}","{entry.quarantineforwardstatus}","{entry.access}","{entry.sdnstatus}","{entry.compressed}","{entry.depth}","{entry.stillinfected}","{entry.definfo}","{entry.defsequincenumber}","{entry.cleaninfo}","{entry.deleteinfo}","{entry.backupod}","{entry.parent}","{entry.guid}","{entry.clientgroup}","{entry.address}","{entry.domainname}","{entry.ntdomain}","{entry.macaddress}","{entry.version}","{entry.remotemachine}","{entry.remotemachineip}","{entry.action1status}","{entry.action2status}","{entry.licensefeaturename}","{entry.licensefeatureversion}","{entry.licenseserialnumber}","{entry.licensefulfillmentid}","{entry.licensestartdate}","{entry.licenseexpirationdate}","{entry.licenselifecycle}","{entry.licenseseatstotal}","{entry.licenseseats}","{entry.errorcode}","{entry.licenseseatsdelta}","{entry.status}","{entry.domainguid}","{entry.sessionguid}","{entry.vbnsessionid}","{entry.logindomain}","{entry.eventdata2}","{entry.erasercategoryid}","{entry.dynamiccategoryset}","{entry.subcategorysetid}","{entry.displaynametouse}","{entry.reputationdisposition}","{entry.reputationconfidence}","{entry.firsseen}","{entry.reputationprevalence}","{entry.downloadurl}","{entry.categoryfordropper}","{entry.cidsstate}","{entry.behaviorrisklevel}","{entry.detectiontype}","{entry.acknowledgetext}","{entry.vsicstate}","{entry.scanguid}","{entry.scanduration}","{entry.scanstarttime}","{entry.targetapptype}","{entry.scancommandguid}","{field113}","{entry.location}","{field115}","{entry.digitalsigner}","{entry.digitalissuer}","{entry.digitalthumbprint}","{field119}","{entry.digitalsn}","{entry.digitaltime}","{field122}","{field123}","{field124}","{field125}","{field126}"'

def read_sep_tag(_, sub=False):
    _ = io.BytesIO(_)
    blob = False
    match = []
    dd = ''
    sddl = ''
    sid = ''
    guid = ''
    dec = ''
    dbguid = ''
    lastguid = ''
    lasttoken = 0
    lastvalue = 0
    hit = None
    virus = ''
    results = ''
    count = 0
    verify = struct.unpack("B", _.read(1))[0]
    _.seek(-1,1)
    while True:
        if sub and verify != 6:
            break
        try:
            code = struct.unpack("B", _.read(1))[0]
        except:
            break
        dec += '{:02x}\n'.format(code)
        if code == 0:
            break
        if code == 1 or code == 10:
            _.seek(-1,1)
            tag = vbnstruct.ASN1_1(_.read(2))
            dec += hexdump_tag(tag.dumps()[1:])
            lastvalue = tag.dumps()[1:]
            
        elif code == 2:
            _.seek(-1,1)
            tag = vbnstruct.ASN1_2(_.read(3))
            dec += hexdump_tag(tag.dumps()[1:])
            
        elif code == 3 or code == 6:
            _.seek(-1,1)
            tag = vbnstruct.ASN1_4(_.read(5))
            dec += hexdump_tag(tag.dumps()[1:])

        elif code == 4:
            _.seek(-1,1)
            tag = vbnstruct.ASN1_8(_.read(9))
            dec += hexdump_tag(tag.dumps()[1:])
        
        elif code == 7:
            size = struct.unpack("<I", _.read(4))[0]
            _.seek(-5,1)
            tag = vbnstruct.ASN1_String_A(_.read(5 + size))
            dec += hexdump_tag(tag.dumps()[1:5])
            string = tag.dumps()[5:].decode('latin-1').replace("\x00", "")
            dec += hexdump_tag(tag.dumps()[5:]) + f'### STRING-A\n      {string}\n'
            if hit == 'virus':
                virus = tag.StringA.decode('latin-1').replace("\x00", "")
                hit = None
            else:
                match.append(tag.StringA.decode('latin-1').replace("\x00", ""))

        elif code == 8:
            size = struct.unpack("<I", _.read(4))[0]
            _.seek(-5,1)
            tag = vbnstruct.ASN1_String_W(_.read(5 + size))
            dec += hexdump_tag(tag.dumps()[1:5])
            string = tag.dumps()[5:].decode('latin-1').replace("\x00", "").replace("\r\n", "\r\n\t  ")
            if lastguid == '00000000000000000000000000000000':
                rstring = string.replace("\r\n\t  ", "\n")

                results += f'{rstring}\n'
            dec += hexdump_tag(tag.dumps()[5:]) + f'### STRING-W\n      {string}\n\n'
            if hit == 'virus':
                virus = tag.StringW.decode('latin-1').replace("\x00", "")
                hit = None
            else:
                match.append(tag.StringW.decode('latin-1').replace("\x00", ""))

        elif code == 9:
            size = struct.unpack("<I", _.read(4))[0]
            _.seek(-5,1)
            if size == 16:
                tag = vbnstruct.ASN1_GUID(_.read(5 + size))
                dec += hexdump_tag(tag.dumps()[1:5])
                dec += f'### GUID\n{hexdump_tag(tag.dumps()[5:])}'
                blob = False
                if re.match(b'\xb9\x1f\x8a\\\\\xb75\\\D\x98\x03%\xfc\xa1W\^q', tag.GUID):
                    hit = 'virus'
            elif blob == True or lastvalue == b'\x0f':
                if lasttoken == 8:
                    tag = vbnstruct.ASN1_4(_.read(5))
                    dec += hexdump_tag(tag.dumps()[1:])
                    blob = True
                else:
                    tag = vbnstruct.ASN1_BLOB(_.read(5 + size))
                    dec += hexdump_tag(tag.dumps()[1:5])
                    dec += f'### BLOB\n{hexdump_tag(tag.dumps()[5:])}'
                    if b'\x00x\xda' in tag.dumps()[5:15]:
                        if tag.dumps()[5:].startswith(b'CMPR'):
                            dec += f'### BLOB Decompressed\n{hexdump_tag(zlib.decompress(tag.dumps()[13:]))}'
                        else:
                            dec += f'### BLOB Decompressed\n{hexdump_tag(zlib.decompress(tag.dumps()[9:]))}\n\n'
                    blob = False
            else:
                tag = vbnstruct.ASN1_4(_.read(5))
                dec += hexdump_tag(tag.dumps()[1:])
                blob = True

        elif code == 15:
            _.seek(-1,1)
            tag = vbnstruct.ASN1_16(_.read(17))
            count += 1
            if count == 1:
                dbguid = '{' + '-'.join([flip(tag.dumps()[1:5].hex()), flip(tag.dumps()[5:7].hex()), flip(tag.dumps()[7:9].hex()), tag.dumps()[9:11].hex(), tag.dumps()[11:17].hex()]).upper() + '}'
            lastguid = tag.dumps()[1:].hex()
            dec += f'\n### GUID\n{hexdump_tag(tag.dumps()[1:])}'
        
        elif code == 16:
            _.seek(-1,1)
            tag = vbnstruct.ASN1_16(_.read(17))
            dec += hexdump_tag(tag.dumps()[1:])
            
        else:
            if lasttoken != 9:
                if lasttoken == 1:
                    _.seek(-1,1)
                    dec = dec[:-3]
                    tag = vbnstruct.ASN1_Error(_.read(16))
                    dec += f'### Error\n{hexdump_tag(tag.dumps())}'
                else:
                    dec = ''
                    break
 
        lasttoken = code
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
    
    if virus == '' and len(match) >= 6:
        virus = match[0]
        del match[0]

    return match, dd, sddl, sid, virus, guid, dec, dbguid, results

def write_report(_, fname):
    for m in re.finditer('(?P<XML><Report Type="(?P<Report>.*?)".*Report>)', _):
        if args.output:
            reportname = args.output+'/ccSubSDK/'+m.group('Report')+'.csv'
        else:
            reportname = m.group('Report')+'.txt'
        header = []
        data = ['']
        if os.path.isfile(reportname):
            data = open(reportname).readlines()
            header = data[0][1:-2].split('","')
            header.remove('File Name')
        reporttype = open(reportname, 'w')
        tree = ET.fromstring(m.group('XML').translate(__vis_filter))
        rows = ''
        for node in tree.iter():
            value = []
            for k, v in node.attrib.items():
                if k == 'Type' or k == 'Count':
                    continue
                else:
                    if k not in header:
                        header.append(k)
                    if len(header) > len(value):
                        diff = len(header) - len(value)
                        value += ' ' * diff
                    pos = header.index(k)
                    value[pos] = v
            if len(value) != 0:
                value = '","'.join(value)
                rows += f'"{fname}","{value}"\n'
        header = '","'.join(header)
        data[0] = f'"File Name","{header}"\n'
        reporttype.writelines(data)
        reporttype.write(rows)
        reporttype.close()

def hexdump_tag(buf, length=16):
    """Return a hexdump output string of the given buffer."""
    res = []

    while buf:
        line, buf = buf[:length], buf[length:]
        hexa = ' '.join(["{:02x}".format(x) for x in line])
        line = line.translate(__vis_filter).decode('utf-8')
        res.append('      %-*s %s' % (length * 3, hexa, line))

    return '\n'.join(res)+'\n\n'

def event_data1(_):
    pos = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]
    _ = _.replace('"', '').split('\t')
    if len(_) < 13:
            diff = 13 - len(_)
            b = [''] * diff
            _.extend(b)
            
    labels = event_data1_labels(_[0])
#    input(labels)
    assert(len(labels) == len(pos))
    acc = 0
    for i in range(len(labels)):
        _.insert(pos[i]+acc, labels[i])
        acc += 1
#    input(_)

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
    else:
        labels = [''] * 12
        
    return labels

def event_data2(_):
    _ = _.replace('"', '').split('\t')
    if len(_) < 17:
            diff = 17 - len(_)
            b = [''] * diff
            _.extend(b)
    
    _[3] = hash_type(_[3])
    _ = '","'.join(_)

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
#        print(f'\033[1;31mEntry mismatch: {count} entries found. Should be {logEntries}.\033[1;0m\n')
        return startEntry, False

    return startEntry, True

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
    if ipHex == '0':
        return '0.0.0.0'
    if len(ipHex) != 8:
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
    guid = [
            '2B5CA624B61E3F408B994BF679001DC2', #BHSvcPlg.dll
            '334FC1F5F2DA574E9BE8A16049417506', #SubmissionsEim.dll
            '38ACED4CA8B2134D83ED4D35F94338BD', #SubmissionsEim.dll
            '5E6E81A4A77338449805BB2B7AB12FB4', #AtpiEim.dll ReportSubmission.dll
            '6AB68FC93C09E744B828A598179EFC83', #IDSxpx86.dll
            '95AAE6FD76558D439889B9D02BE0B850', #IDSxpx86.dll
            '8EF95B94E971E842BAC952B02E79FB74', #AVModule.dll
            'A72BBCC1E52A39418B8BB591BDD9AE76', #RepMgtTim.dll
            '6A007A980A5B0A48BDFC4D887AEACAB0'  #IDSxpx86.dll
           ]
           
    headersize = len(f.readline())
    if headersize == 0:
        print(f'\033[1;33mSkipping {f.name}. Unknown File Type. \033[1;0m\n')
        return 11, 0, 0, 1, 0, 0, 0, 0
    f.seek(0)
    sheader = f.read(16).hex()
    if sheader[0:16] == '3216144c01000000':
        return 9, 0, 0, 1, 0, 0, 0, 0
    if re.search('\{[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\}$', f.name, re.IGNORECASE):
#        print("yes")
#    if sheader.upper() in guid:
        return 10, 0, 0, 1, 0, 0, 0, 0
    f.seek(0)
    if headersize == 55:
        logType = 5
        maxSize = read_unpack_hex(f, 0, 8)
        field3 = read_unpack_hex(f, 9, 8)
        cLogEntries = read_unpack_hex(f, 18, 8)
        field5 = read_unpack_hex(f, 27, 8)
        field6 = read_unpack_hex(f, 36, 8)
        tLogEntries = 'N\A'
        maxDays = read_unpack_hex(f, 45, 8)
        return logType, maxSize, field3, cLogEntries, field5, field6, tLogEntries, maxDays

    if headersize == 72:
        logType = read_unpack_hex(f, 0, 8)
        maxSize = read_unpack_hex(f, 9, 8)
        field3 = read_unpack_hex(f, 18, 8)
        cLogEntries = read_unpack_hex(f, 27, 8)
        field5 = read_unpack_hex(f, 36, 8)
        field6 = 'N\A'
        tLogEntries = read_unpack_hex(f, 45, 16)
        maxDays = read_unpack_hex(f, 62, 8)
        return logType, maxSize, field3, cLogEntries, field5, field6, tLogEntries, maxDays

    try:
        from_symantec_time(f.readline().split(b',')[0].decode("utf-8", "ignore"), 0)
        return 6, 0, 0, 1, 0, 0, 0, 0
    except:
        pass
    try:
        f.seek(388, 0)
        from_symantec_time(f.read(2048).split(b',')[0].decode("utf-8", "ignore"), 0)
        return 7, 0, 0, 1, 0, 0, 0, 0
    except:
        pass
    try:
        f.seek(4100, 0)
        from_symantec_time(f.read(2048).split(b',')[0].decode("utf-8", "ignore"), 0)
        return 8, 0, 0, 1, 0, 0, 0, 0  
    except:
        print(f'\033[1;33mSkipping {f.name}. Unknown File Type. \033[1;0m\n')
        return 11, 0, 0, 1, 0, 0, 0, 0
        
def parse_syslog(f, logEntries):
    startEntry = 72
    nextEntry = read_unpack_hex(f, startEntry, 8)
    entry = LogFields()
    count = 0

    while True:
        data = '""'
        entry.size = ''
        logEntry = read_log_entry(f, startEntry, nextEntry).split(b'\t')
        entry.dateAndTime = from_win_64_hex(logEntry[1])
        entry.severity =  sys_severity(int(logEntry[4], 16))
        eds = int(logEntry[5].decode("utf-8", "ignore"), 16)
        entry.summary = logEntry[6].decode("utf-8", "ignore").replace('"', '""')
        entry.type = logEntry[7].decode("utf-8", "ignore")

        if eds == 11:
            entry.size = int(logEntry[8][2:10], 16)

        if eds > 11:
            data = read_log_data(logEntry[8], 0)
            
        try:
            entry.location = logEntry[9].decode("utf-8", "ignore")
        except:
            entry.location = ''

        syslog.write(f'"{f.name}","{int(logEntry[0].decode("utf-8", "ignore"), 16)}","{entry.dateAndTime}","{sec_event_id(logEntry[2].decode("utf-8", "ignore"))}","{logEntry[3].decode("utf-8", "ignore")}","{entry.severity}","{entry.summary}","{eds}","{entry.type}","{entry.size}","{entry.location}",{data}\n')

        if len(data) > 2:
            timeline.write(f'"{f.name}","","","","","",{data}\n')
        
        count += 1

        if count == logEntries:
            break

        startEntry, moreData = entry_check(f, startEntry, nextEntry)
        
        if moreData == False:
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
        data = ''
        if int(logEntry[12], 16) == 0:
            logData = ['']
        else:
            #Field27 might be a better indicator of data type (0=logline ,2=base64)?
            #Field38 might be a better indicator of data type (0=logline ,1=base64)?
            if re.match(b'^([A-Za-z0-9+/]{4})*([A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{2}==)?$', logEntry[16][:int(logEntry[12], 16)]):
                logData = ['']
                parsed = json.loads(base64.b64decode(logEntry[16][:int(logEntry[12], 16)]).decode("utf-8", "ignore"))
                data = json.dumps(parsed, indent=4, sort_keys=True)
                data = data.replace('"', '""')
            else:
                logData = read_log_data(logEntry[16][:int(logEntry[12], 16)], 0).split(",")

        entry.dateAndTime = from_win_64_hex(logEntry[1])
        entry.eventtype = sec_event_type(int(logEntry[2], 16))
        entry.severity =  sec_severity(int(logEntry[3], 16))
        entry.localhost = from_hex_ip(logEntry[4])
        entry.remotehost = from_hex_ip(logEntry[5])
        entry.protocol = sec_network_protocol(int(logEntry[6], 16))
        entry.direction = log_direction(int(logEntry[8], 16))
        entry.begintime = from_win_64_hex(logEntry[9])
        entry.endtime = from_win_64_hex(logEntry[10])
        entry.occurrences = int(logEntry[11], 16)
        entry.description = logEntry[13].decode("utf-8", "ignore")
        entry.application = logEntry[15].decode("utf-8", "ignore")
        logEntry2 = logEntry[16][int(logEntry[12], 16):].split(b'\t')
        entry.localmac = logEntry2[1].hex()

        if len(entry.localmac) < 32:
            while True:
                logEntry2[1] = logEntry2[1] + b'\t'
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
        
        #SEP14.3.0.1
        try:
            entry.urlhidlevel = logEntry2[23].decode("utf-8", "ignore")
            entry.urlriskscore = logEntry2[24].decode("utf-8", "ignore")
            entry.urlcategories = logEntry2[25].decode("utf-8", "ignore")
        except:
            pass
            
        seclog.write(f'"{f.name}","{int(logEntry[0].decode("utf-8", "ignore"), 16)}","{entry.dateAndTime}","{entry.eventtype}","{entry.severity}","{entry.direction}","{entry.protocol}","{entry.remotehost}","{entry.remoteport}","{entry.remotemac}","{entry.localhost}","{entry.localport}","{entry.localmac}","{entry.application}","{entry.signatureid}","{entry.signaturesubid}","{entry.signaturename}","{entry.intrusionurl}","{entry.xintrusionpayloadurl}","{entry.user}","{entry.userdomain}","{entry.location}","{entry.occurrences}","{entry.endtime}","{entry.begintime}","{entry.hash}","{entry.description}","{logEntry[7].decode("utf-8", "ignore")}","{int(logEntry[12], 16)}","{logEntry[14].decode("utf-8", "ignore")}","{logEntry2[8].decode("utf-8", "ignore")}","{logEntry2[9].decode("utf-8", "ignore")}","{REMOTE_HOST_IPV6}","{LOCAL_HOST_IPV6}","{logEntry2[17].decode("utf-8", "ignore")}","{logEntry2[18].decode("utf-8", "ignore")}","{logEntry2[19].decode("utf-8", "ignore")}","{logEntry2[20].decode("utf-8", "ignore")}","{logEntry2[21].decode("utf-8", "ignore")}","{entry.urlhidlevel}","{entry.urlriskscore}","{entry.urlcategories}","{data}",{",".join(logData)}\n')

        if len(logData) > 1:
            timeline.write(f'"{f.name}","{int(logEntry[12], 16)}","","","","",{",".join(logData)}\n')

        count += 1

        if count == logEntries:
            break
       
        startEntry, moreData = entry_check(f, startEntry, nextEntry)
        
        if moreData == False:
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
        if entry.protocol == "ICMP":
            typeName, codeDescription = icmp_type_code(entry.localport, entry.remoteport)
            entry.protocol = f'{entry.protocol} [type={entry.localport}, code={entry.remoteport}]\r\nName:{typeName}\r\nDescription:{codeDescription}'
            entry.localport = 0
            entry.remoteport = 0
        if entry.protocol == "ETHERNET":
            entry.protocol = f'{entry.protocol} [type={hex(entry.localport)}]\r\nDescription: {eth_type(entry.localport)}'
            entry.localport = 0
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
        
        try:
            field33 = logEntry[32].decode("utf-8", "ignore")
            field34 = logEntry[33].decode("utf-8", "ignore")
        except:
            field33 = ''
            field34 = ''
        tralog.write(f'"{f.name}","{int(logEntry[0].decode("utf-8", "ignore"), 16)}","{entry.dateAndTime}","{entry.action}","{entry.severity}","{entry.direction}","{entry.protocol}","{entry.remotehost}","{entry.remotemac}","{entry.remoteport}","{entry.localhost}","{entry.localmac}","{entry.localport}","{entry.application}","{entry.user}","{entry.userdomain}","{entry.location}","{entry.occurrences}","{entry.begintime}","{entry.endtime}","{entry.rule}","{logEntry[12].decode("utf-8", "ignore")}","{logEntry[14].decode("utf-8", "ignore")}","{logEntry[15].decode("utf-8", "ignore")}","{logEntry[23].decode("utf-8", "ignore")}","{logEntry[24].decode("utf-8", "ignore")}","{from_hex_ipv6(logEntry[25])}","{from_hex_ipv6(logEntry[26])}","{logEntry[27].decode("utf-8", "ignore")}","{logEntry[28].decode("utf-8", "ignore")}","{logEntry[29].decode("utf-8", "ignore")}","{logEntry[30].decode("utf-8", "ignore")}","{logEntry[31].decode("utf-8", "ignore")}","{field33}","{field34}"\n')
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

                if len(logEntry) == 20:
                    break

        entry.dateAndTime = from_win_64_hex(logEntry[1])
        eventId = raw_event_id(int(logEntry[2].decode("utf-8", "ignore"), 16))
        entry.localhost = from_hex_ip(logEntry[3])
        entry.remotehost = from_hex_ip(logEntry[4])
        entry.localport = int(logEntry[5], 16)
        entry.remoteport = int(logEntry[6], 16)
        plength = int(logEntry[7], 16)
        entry.direction = log_direction(int(logEntry[8], 16))
        entry.action = log_c_action(int(logEntry[9], 16))
        entry.application = logEntry[12].decode("utf-8", "ignore")
        entry.packetdecode = hexdump(logEntry[13]).replace('"', '""')
        entry.rule = logEntry[14].decode("utf-8", "ignore")
        entry.packetdump = ''
        
        rawlog.write(f'"{f.name}","{int(logEntry[0].decode("utf-8", "ignore"), 16)}","{entry.dateAndTime}","{entry.remotehost}","{entry.remoteport}","{entry.localhost}","{entry.localport}","{entry.direction}","{entry.action}","{entry.application}","{entry.rule}","{entry.packetdump}","{entry.packetdecode}","{eventId}","{plength}","{logEntry[10].decode("utf-8", "ignore")}","{logEntry[11].decode("utf-8", "ignore")}","{logEntry[15].decode("utf-8", "ignore")}","{logEntry[16].decode("utf-8", "ignore")}","{logEntry[17].decode("utf-8", "ignore")}","{logEntry[18].decode("utf-8", "ignore")}","{logEntry[19].decode("utf-8", "ignore")}"\n')
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
            
            if len(check) == 0:
                break
                
            if check is b'0':
                f.seek(startEntry)

        if len(check) == 0:
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
        entry.filesize = int(logEntry[24], 16)
        ipv6 = from_hex_ipv6(logEntry[26])
        processlog.write(f'"{f.name}","{int(logEntry[0].decode("utf-8", "ignore"), 16)}","{entry.dateAndTime}","{entry.severity}","{entry.action}","{entry.testmode}","{entry.description}","{entry.api}","{entry.rulename}","{entry.ipaddress}","{ipv6}","{entry.callerprocessid}","{entry.callerprocess}","{entry.deviceinstanceid}","{entry.target}","{entry.filesize}","{entry.user}","{entry.userdomain}","{entry.location}","{process_event_id(int(logEntry[2].decode("utf-8", "ignore"), 16))}","{logEntry[8].decode("utf-8", "ignore")}","{from_win_64_hex(logEntry[9])}","{from_win_64_hex(logEntry[10])}","{logEntry[14].decode("utf-8", "ignore")}","{logEntry[15].decode("utf-8", "ignore")}","{logEntry[20].decode("utf-8", "ignore")}","{logEntry[21].decode("utf-8", "ignore")}","{logEntry[25].decode("utf-8", "ignore")}"\n')
        count += 1

        if count == logEntries:
            break

        startEntry = startEntry + nextEntry
        f.seek(startEntry)
        check = f.read(1)

        if len(check) == 0:
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
 
        startEntry, moreData = entry_check(f, startEntry, nextEntry)
        
        if moreData == False:
            print(f'\033[1;31mEntry mismatch: {count} entries found. Should be {logEntries}.\033[1;0m\n')
            break

        nextEntry = read_unpack_hex(f, startEntry, 8)

def parse_tamper_protect(logData, logEntry, fname):
    # need action
    entry = LogFields()
    
    entry.time = logData[0]
    entry.computer = logData[4]
    entry.user = logData[5]
    entry.event = log_tp_event(logData[17], logData[23])
    entry.actor = f'{logData[21]} (PID {logData[19]})'
    entry.targetprocess = f'{logData[29]} (PID {logData[25]})'
    entry.target = logData[27]

    tamperProtect.write(f'"{fname}","{entry.computer}","{entry.user}","{entry.action}","{entry.event}","{entry.actor}","{entry.target}","{entry.targetprocess}","{entry.time}\n')

def parse_daily_av(f, logType, tz):
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
        logEntry = read_log_data(logEntry, tz)
        
        if logEntry.split('","')[1] == 'SECURITY_SYMPROTECT_POLICYVIOLATION':
            parse_tamper_protect(logEntry.split('","'), logEntry, f.name)
        
        timeline.write(f'"{f.name}","","","","","",{logEntry}\n')

        if logType == 7 or logType == 8:
            break
            
        logEntry = f.readline()

def parse_vbn(f, logType, tz):
    logEntry = ''
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
    vbnv = ''
    garbage = None
    header = 0
    footer = 0
    qfs = 0
    junkfs = 0
    f.seek(0, 0)
    qfm_offset = struct.unpack('i', f.read(4))[0]
    f.seek(0, 0)
    
    if logType == 7:
        f.seek(388, 0)
        logEntry = f.read(2048).split(b'\x00\x00')[0]

    if logType == 8:
        f.seek(4100, 0)
        logEntry = f.read(1112).split(b'\x00\x00')[0]
    
    logEntry = read_log_data(logEntry, tz)
    f.seek(0, 0)

    if qfm_offset == 3676:
        vbnmeta = vbnstruct.VBN_METADATA_V1(f)
        vbnv = 1
    if qfm_offset == 4752:
        vbnmeta = vbnstruct.VBN_METADATA_V2(f)
        vbnv = 2
    if qfm_offset == 15100:
        vbnmeta = vbnstruct.VBN_METADATA_Linux(f)

    if args.struct:
        sout = ''
        for k, v in vbnmeta._values.items():
            sout += str(v).replace('"', '""')+'","'

    wDescription = vbnmeta.WDescription.rstrip('\0')
    description = vbnmeta.Description.rstrip(b'\x00').decode("utf-8", "ignore")
    storageName = vbnmeta.Storage_Name.rstrip(b'\x00').decode("utf-8", "ignore")
    storageKey = vbnmeta.Storage_Key.rstrip(b'\x00').decode("utf-8", "ignore")
    uniqueId = '{' + '-'.join([flip(vbnmeta.Unique_ID.hex()[:8]), flip(vbnmeta.Unique_ID.hex()[8:12]), flip(vbnmeta.Unique_ID.hex()[12:16]), vbnmeta.Unique_ID.hex()[16:20], vbnmeta.Unique_ID.hex()[20:32]]).upper() + '}'
    rtid = remediation_type_desc(vbnmeta.Remediation_Type)

    if args.hex_dump:
        cstruct.dumpstruct(vbnmeta)

    if vbnmeta.Record_Type == 0:
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
            if args.struct:
                for k, v in qdata_location._values.items():
                    sout += str(v).replace('"', '""')+'","'
            if args.hex_dump:
                cstruct.dumpstruct(qdata_location)
            pos = vbnmeta.QFM_HEADER_Offset + qdata_location.QData_Location_Offset
            file_size = qdata_location.QData_Location_Size - qdata_location.QData_Location_Offset
            f.seek(pos)
            if args.extract:
                print('\n           #######################################################')
                print('           #######################################################')
                print('           ##                                                   ##')
                print('           ##    Extracting quarantine file. Please wait....    ##')
                print('           ##                                                   ##')
                print('           #######################################################')
                print('           #######################################################\n')                    
            if args.extract or args.quarantine_dump:
                qfile = xor(f.read(file_size), 0x5A)

            f.seek(pos + file_size)
            #need to properly parse
            qdata_info = vbnstruct.QData_Info(xor(f.read(), 0x5A).encode('latin-1'))
            if args.struct:
                for k, v in qdata_info._values.items():
                    sout += str(v).replace('"', '""')+'","'
            if args.hex_dump:
                cstruct.dumpstruct(qdata_info)

        else:
            f.seek(-8, 1)
            if args.extract or args.quarantine_dump:
                qfile = xor(f.read(), 0x5A)
        if args.struct:
            if vbnv == 1:
                rt0v1.write(f'"{f.name}","{sout[:-2]}\n')
            if vbnv == 2:
                rt0v2.write(f'"{f.name}","{sout[:-2]}\n')

    if vbnmeta.Record_Type == 1:
        if args.hex_dump:
            print('\n           #######################################################')
            print('           #######################################################')
            print('           ##                                                   ##')
            print('           ##     Quarantine File Metadata Structure (ASN1)     ##')
            print('           ##                                                   ##')
            print('           #######################################################')
            print('           #######################################################\n')
        tags, dd, sddl, sid, virus, guid, dec, dbguid, results = read_sep_tag(f.read())

        if args.struct:
            if vbnv == 1:
                rt1v1.write(f'"{f.name}","{sout[:-2]}\n')
            if vbnv == 2:
                rt1v2.write(f'"{f.name}","{sout[:-2]}\n')
        
        if args.extract or args.quarantine_dump:
            print(f'\033[1;31mRecord type 1 does not contain quarantine data.\033[1;0m\n')
    
    if vbnmeta.Record_Type == 2:
        f.seek(vbnmeta.QFM_HEADER_Offset, 0)
        f.seek(8, 1)
        qfm_size = xor(f.read(8), 0x5A).encode('latin-1')
        qfm_size = struct.unpack('q', qfm_size)[0]
        f.seek(-16, 1)
        qfm = vbnstruct.Quarantine_File_Metadata_Header(xor(f.read(qfm_size), 0x5A).encode('latin-1'))
        if args.struct:
            for k, v in qfm._values.items():
                sout += str(v).replace('"', '""')+'","'
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
            print('           ##     Quarantine File Metadata Structure (ASN1)     ##')
            print('           ##                                                   ##')
            print('           #######################################################')
            print('           #######################################################\n')
        tags, dd, sddl, sid, virus, guid, dec, dbguid, results = read_sep_tag(xor(f.read(qfm.QFM_Size), 0x5A).encode('latin-1'))

        pos = qfm.QFM_Size_Header_Size + vbnmeta.QFM_HEADER_Offset
        f.seek(pos)
        qfi = vbnstruct.Quarantine_File_Info(xor(f.read(7), 0x5A).encode('latin-1'))
        if args.hex_dump:
            cstruct.dumpstruct(qfi)
        if args.struct:
            for k, v in qfi._values.items():
                sout += str(v).replace('"', '""')+'","'
        if qfi.Tag2_Data == 1:
            qfi2 = vbnstruct.Quarantine_File_Info2(xor(f.read(1), 0x5A).encode('latin-1'))
            if args.hex_dump:
                cstruct.dumpstruct(qfi2)
            if args.struct:
                for k, v in qfi2._values.items():
                    sout += str(v).replace('"', '""')+'","'
            if qfi2.Tag3 == 8:
                qfi3_size = struct.unpack('i', xor(f.read(4), 0x5A).encode('latin-1'))[0] + 27
                f.seek(-4, 1)
                qfi3 = vbnstruct.Quarantine_File_Info3(xor(f.read(qfi3_size), 0x5A).encode('latin-1'))
                sha1 = qfi3.SHA1.decode('latin-1').replace("\x00", "")
                if args.hex_dump:
                    cstruct.dumpstruct(qfi3)
                if args.struct:
                    for k, v in qfi2._values.items():
                        sout += str(v).replace('"', '""')+'","'
            
        dataType = xor(f.read(1), 0x5A).encode('latin-1')

        if dataType == b'\x08':
            pos += 35 + qfi3.Hash_Size
            f.seek(pos)
            qfi4_size = struct.unpack('i', xor(f.read(4), 0x5A).encode('latin-1'))[0] + 18
            f.seek(-4, 1)
            qfi4 =  vbnstruct.Quarantine_File_Info4(xor(f.read(qfi4_size), 0x5A).encode('latin-1'))
            if args.struct:
                for k, v in qfi4._values.items():
                    sout += str(v).replace('"', '""')+'","'
            sddl = sddl_translate(qfi4.Security_Descriptor.decode('latin-1').replace("\x00", ""))
            if args.hex_dump:
                cstruct.dumpstruct(qfi4)
            pos += 19 + qfi4.Security_Descriptor_Size
            f.seek(pos)
        
        else:
            if args.struct:
                sout += '","","","","","","","'
        
        if dataType == b'\t':  #actually \x09
            garbage = qfs - vbnmeta.Quarantine_File_Size
            pos += 35 + qfi3.Hash_Size
            f.seek(pos)

        try:
            chunk = vbnstruct.chunk(xor(f.read(5), 0x5A).encode('latin-1'))
            pos += 5
            f.seek(pos)
            if garbage is not None:
                junk = vbnstruct.Junk_Header(xor(f.read(1000), 0xA5).encode('latin-1'))
                if args.struct:
                    for k, v in junk._values.items():
                        sout += str(v).replace('"', '""')+'","'
                    
                junkfs = junk.File_Size
                if args.hex_dump:
                    cstruct.dumpstruct(junk)
                f.seek(pos)

            if args.hex_dump or args.extract or args.struct or args.quarantine_dump:
                while True:
                    if chunk.Data_Type == 9:
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
                        if args.struct:
                            for k, v in jf._values.items():
                                sout += str(v).replace('"', '""')+'","'
                        if args.hex_dump:
                            cstruct.dumpstruct(jf)
                    except:
                        pass
                
        except:
            if args.extract:
                print(f'\033[1;31mDoes not contain quarantine data. Clean by Deletion.\033[1;0m\n')
                print(f'\033[1;32mFinished parsing {f.name} \033[1;0m\n')
            pass
            
        if args.struct:
            if vbnv == 1:
                rt2v1.write(f'"{f.name}","{sout[:-2]}\n')
            if vbnv == 2:
                rt2v2.write(f'"{f.name}","{sout[:-2]}\n')

    if args.quarantine_dump and len(qfile) > 0:
        if (header or qfs) == 0:
            test = hexdump_tag(qfile.encode('latin-1'))
        else:
            test = hexdump_tag(qfile[header:qfs].encode('latin-1'))
        print(test)
    
    if args.extract and len(qfile) > 0:
        if args.output:
            output = open(args.output + '/' + os.path.basename(description) + '.vbn','wb+')
        else:
            output = open(os.path.basename(description) + '.vbn','wb+')
        
        if (header or qfs) == 0:
            output.write(bytes(qfile, encoding= 'latin-1'))
        else:
            output.write(bytes(qfile[header:qfs], encoding= 'latin-1'))    

    if not (args.extract or args.hex_dump):
        try:
            modify = from_filetime(vbnmeta.Date_Modified)
            create = from_filetime(vbnmeta.Date_Created)
            access = from_filetime(vbnmeta.Date_Accessed)
        except:
            modify = from_unix_sec(vbnmeta.Date_Modified)
            create = from_unix_sec(vbnmeta.Date_Created)
            access = from_unix_sec(vbnmeta.Date_Accessed)
            vbin = from_unix_sec(vbnmeta.VBin_Time)

        quarantine.write(f'"{f.name}","{description}","{vbnmeta.Record_ID}","{modify}","{create}","{access}","{vbin}","{storageName}","{vbnmeta.Storage_Instance_ID}","{storageKey}","{vbnmeta.Quarantine_File_Size}","{from_unix_sec(vbnmeta.Date_Created_2)}","{from_unix_sec(vbnmeta.Date_Accessed_2)}","{from_unix_sec(vbnmeta.Date_Modified_2)}","{from_unix_sec(vbnmeta.VBin_Time_2)}","{uniqueId}","{vbnmeta.Record_Type}","{hex(vbnmeta.Quarantine_Session_ID)[2:].upper()}","{rtid}","{wDescription}","{sddl}","{sha1}","{qfs}","{junkfs}","{dd}","{virus}","{guid}","{tags}","{sid}",{logEntry}\n')

def extract_sym_submissionsidx(f):
    f.seek(48)
    cnt = 0
    while f.read(4) == b'@\x99\xc6\x89':
        f.seek(20,1)
        len1 = struct.unpack('i', f.read(4))[0]
        len2 = struct.unpack('i', f.read(4))[0]
        print(f'\033[1;35m\tSubmission {cnt} len1={len1} len2={len2}\033[1;0m\n')
        f.seek(8,1)   
        if args.output:
            if not os.path.exists(args.output + '/ccSubSDK/submissions'):
                os.makedirs(args.output + '/ccSubSDK/submissions')
            newfilename = open(args.output + '/ccSubSDK/submissions/submissions.idx_Symantec_submission_['+str(cnt)+']_idx.out', 'wb')
        else:
            if not os.path.exists('ccSubSDK/submissions'):
                os.makedirs('ccSubSDK/submissions')
            newfilename = open('ccSubSDK/submissions/submissions.idx_Symantec_submission_['+str(cnt)+']_idx.out', 'wb')
        key = f.read(16)
        data = f.read(len1 - 16)
        dec = blowfishit(data,key)
        newfilename.write(dec.encode('latin-1'))
        dec = read_sep_tag(dec.encode('latin-1'), sub=True)
        if dec[6] == '':
            newfilename.close()
            os.remove(newfilename.name)
            f.seek(-len1 - 40, 1)
            data = f.read(len1 + 40)
            extract_sym_submissionsidx_sub(data, cnt, len1)
            cnt += 1
            continue
        if args.output:
            newfilename = open(args.output + '/ccSubSDK/submissions/submissions.idx_Symantec_submission_['+str(cnt)+']_idx.met', 'wb')
        else:
            newfilename = open('ccSubSDK/submissions/submissions.idx_Symantec_submission_['+str(cnt)+']_idx.met', 'wb')
        newfilename.write(dec[6].encode('latin-1'))
        read_submission(dec[8], dec[7])
        print(f'\033[1;32m\tFinished parsing Submission {cnt}\033[1;0m\n')
        cnt += 1
        
def extract_sym_submissionsidx_sub(f, cnt, len1):
    print(f'\033[1;32m\t\tParsing sub-entries for Submission {cnt}\033[1;0m\n')
    print(f'\033[1;35m\t\tSubmission {cnt}-0\033[1;0m\n')
    if args.output:
            newfilename = open(args.output + '/ccSubSDK/submissions/submissions.idx_Symantec_submission_['+str(cnt)+'-0]_idx.out', 'wb')
    else:
        newfilename = open('ccSubSDK/submissions/submissions.idx_Symantec_submission_['+str(cnt)+'-0]_idx.out', 'wb')
    subcnt = 1
    f = io.BytesIO(f)
    try:
        pos = [(m.start(0)) for m in re.finditer(b'@\x99\xc6\x89', f.read())][1]
        print(f'\033[1;35m\t\tSubmission {cnt}-0 len1={pos} len2=0\033[1;0m\n')
    except:
        f.seek(0)
        print(f'\033[1;35m\t\tSubmission {cnt}-0 len1={len1} len2=0\033[1;0m\n')
        newfilename.write(f.read())
        print(f'\033[1;32m\t\tFinished parsing Submission {cnt}-0\033[1;0m\n')
        return
    f.seek(0)   
    newfilename.write(f.read(pos))
    print(f'\033[1;32m\t\tFinished parsing Submission {cnt}-0\033[1;0m\n')
    while f.read(4) == b'@\x99\xc6\x89':
        f.seek(20,1)
        len1 = struct.unpack('i', f.read(4))[0]
        len2 = struct.unpack('i', f.read(4))[0]
        print(f'\033[1;35m\t\tSubmission {cnt}-{subcnt} len1={len1} len2={len2}\033[1;0m\n')
        f.seek(8,1)   
        if args.output:
            newfilename = open(args.output + '/ccSubSDK/submissions/submissions.idx_Symantec_submission_['+str(cnt)+'-'+str(subcnt)+']_idx.out', 'wb')
        else:
            newfilename = open('ccSubSDK/submissions/submissions.idx_Symantec_submission_['+str(cnt)+'-'+str(subcnt)+']_idx.out', 'wb')
        key = f.read(16)
        data = f.read(len1 - 16)
        dec = blowfishit(data,key)
        newfilename.write(dec.encode('latin-1'))
        dec = read_sep_tag(dec.encode('latin-1'), sub=True)
        if args.output:
            newfilename = open(args.output + '/ccSubSDK/submissions/submissions.idx_Symantec_submission_['+str(cnt)+'-'+str(subcnt)+']_idx.met', 'wb')
        else:
            newfilename = open('ccSubSDK/submissions/submissions.idx_Symantec_submission_['+str(cnt)+'-'+str(subcnt)+']_idx.met', 'wb')
        newfilename.write(dec[6].encode('latin-1'))
        read_submission(dec[8], dec[7])
        print(f'\033[1;32m\t\tFinished parsing Submission {cnt}-{subcnt}\033[1;0m\n')
        subcnt += 1

def extract_sym_ccSubSDK(f):
    f.seek(0)
    GUID = f.read(16).hex()
    if args.output:
        if not os.path.exists(args.output+'/ccSubSDK/'+GUID):
            os.makedirs(args.output+'/ccSubSDK/'+GUID)
        newfilename = open(args.output + '/ccSubSDK/' + GUID + '/' + os.path.basename(f.name)+'_Symantec_ccSubSDK.out', 'wb')
    else:
        if not os.path.exists('ccSubSDK/'+GUID):
            os.makedirs('ccSubSDK/'+GUID)
        newfilename = open('ccSubSDK/' + GUID + '/' + os.path.basename(f.name)+'_Symantec_ccSubSDK.out', 'wb')
    key = f.read(16)
    data = f.read()
    dec = blowfishit(data,key)
    newfilename.write(dec.encode('latin-1'))
    dec = read_sep_tag(dec.encode('latin-1'))

    write_report(dec[6], os.path.basename(f.name))

    if args.output:
        newfilename = open(args.output + '/ccSubSDK/' + GUID + '/' + os.path.basename(f.name)+'_Symantec_ccSubSDK.met', 'wb')
    else:
        newfilename = open('ccSubSDK/' + GUID + '/' + os.path.basename(f.name)+'_Symantec_ccSubSDK.met', 'wb')
    newfilename.write(dec[6].encode('latin-1'))
    
def blowfishit(data,key):
    dec = ''
    cipher = blowfish.Cipher(key, byte_order = "little")
    data = io.BytesIO(data)
    while data:
        dec += str(cipher.decrypt_block(data.read(8)).decode('latin-1'))
        check = data.read(1)
        if len(check) == 0:
            break
        data.seek(-1,1)
    return dec

def utc_offset(_):
    tree = ET.parse(_)
    root = tree.getroot()
    
    for SSAUTC in root.iter('SSAUTC'):
        utc = SSAUTC.get('Bias')

    return int(utc)

def logo():
    print("\033[1;93m____________\033[1;0m")     
    print("\033[1;93m|   |  |   |\033[1;0m")            
    print("\033[1;93m|   |  |   |\033[1;97m   ____  _____ ____")                                 
    print("\033[1;93m|   |  |   |\033[1;97m  / ___|| ____|  _ \ _ __   __ _ _ __ ___  ___ _ __ ")
    print("\033[1;93m|   |  |\033[1;92m___\033[1;93m|\033[1;97m  \___ \|  _| | |_) | '_ \ / _` | '__/ __|/ _ \ '__|")
    print("\033[1;93m \  |  \033[1;92m/ _ \ \033[1;97m  ___) | |___|  __/| |_) | (_| | |  \__ \  __/ |")   
    print("\033[1;93m  \ | \033[1;92m| (_) |\033[1;97m |____/|_____|_|   | .__/ \__,_|_|  |___/\___|_| v2.0")   
    print("\033[1;93m    \  \033[1;92m\___/\033[1;97m                    |_|")                             
    print("\033[1;93m     \/\033[1;0m")
    print("")     

def main():

    for filename in filenames:
        print(f'\033[1;35mStarted parsing {filename} \033[1;0m\n')
        try:
            with open(filename, 'rb') as f:
                logType, maxSize, field3, cLogEntries, field5, field6, tLogEntries, maxDays = parse_header(f)
                try:
                    if logType <= 5:
                            settings.write(f'"{filename}","{maxSize}","{cLogEntries}","{tLogEntries}","{maxDays}","{field3}","{field5}","{field6}"\n')
                    if cLogEntries == 0:
                        print(f'\033[1;33mSkipping {filename}. Log is empty. \033[1;0m\n')
                        continue

                    if logType == 0:
                        parse_syslog(f, cLogEntries)

                    if logType == 1:
                        parse_seclog(f, cLogEntries)

                    if logType == 2:
                        parse_tralog(f, cLogEntries)

                    if logType == 3:
                        parse_raw(f, cLogEntries)

                    if logType == 4:
                        #need better parsing(missing data)
                        parse_processlog(f, cLogEntries)

                    if logType == 5:
                        parse_avman(f, cLogEntries)

                    if logType == 6:
                        parse_daily_av(f, logType, args.timezone)

                    if logType == 7:
                        parse_vbn(f, logType, args.timezone)
                        if not (args.extract or args.hex_dump):
                            parse_daily_av(f, logType, args.timezone)
                        
                    if logType == 8:
                        parse_vbn(f, logType, args.timezone)
                        if not (args.extract or args.hex_dump):
                            parse_daily_av(f, logType, args.timezone)

                    if logType == 9:
                        extract_sym_submissionsidx(f)
                        
                    if logType == 10:
                        extract_sym_ccSubSDK(f)

                    if logType == 11:
                        continue

                    print(f'\033[1;32mFinished parsing {filename} \033[1;0m\n')

                except Exception as e:
                    print(f'\033[1;31mProblem parsing {filename}: {e} \033[1;0m\n')
                    continue

        except Exception as e:
            print(f'\033[1;33mSkipping {filename}. \033[1;31m{e}\033[1;0m\n')

    print(f'\033[1;37mProcessed {len(filenames)} file(s) in {format((time.time() - start), ".4f")} seconds \033[1;0m')
    sys.exit()

logo()
start = time.time()
parser = argparse.ArgumentParser()
parser.add_argument("-f", "--file", help="File to be parsed")
parser.add_argument("-d", "--dir", help="Directory to be parsed")
parser.add_argument("-e", "--extract", help="Extract quarantine file from VBN if present.", action="store_true")
parser.add_argument("-hd", "--hex-dump", help="Dump hex output of VBN to screen.", action="store_true")
parser.add_argument("-qd", "--quarantine-dump", help="Dump hex output of quarantine to screen.", action="store_true")
parser.add_argument("-o", "--output", help="Directory to output files to. Default is current directory.")
parser.add_argument("-a", "--append", help="Append to output files.", action="store_true")
parser.add_argument("-r", "--registrationInfo", help="Path to registrationInfo.xml")
parser.add_argument("-tz", "--timezone", type=int, help="UTC offset")
parser.add_argument("-k", "--kape", help="Kape mode", action="store_true")
parser.add_argument("-s", "--struct", help="Output structures to csv", action="store_true")

if len(sys.argv) == 1:
    parser.print_help()
    # parser.print_usage() # for just the usage line
    parser.exit()

args = parser.parse_args()

regex =  re.compile(r'\\Symantec Endpoint Protection\\(Logs|.*\\Data\\Logs|.*\\Data\\Quarantine|.*\\Data\\CmnClnt\\ccSubSDK)')
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
                        print(f'\033[1;36m{os.path.join(path, name)} found. Attempting to apply timezone offset.\n \033[1;0m')
                        args.timezone = utc_offset(os.path.join(path, name))
                        print(f'\033[1;32mTimezone offset of {args.timezone} applied successfully. \033[1;0m\n')
                    except Exception as e:
                        print(f'\033[1;31mUnable to apply offset. Timestamps will not be adjusted. {e}\033[1;0m\n')
                        pass

        if regex.findall(path):
            for name in files:
                filenames.append(os.path.join(path, name))

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
                    print(f'\033[1;36m{os.path.join(path, name)} found. Attempting to apply timezone offset.\n \033[1;0m')
                    args.timezone = utc_offset(os.path.join(path, name))
                    print(f'\033[1;32mTimezone offset of {args.timezone} applied successfully. \033[1;0m\n')
                except Exception as e:
                    print(f'\033[1;31mUnable to apply offset. Timestamps will not be adjusted. {e}\033[1;0m\n')
                    pass

            filenames.append(os.path.join(path, name))

if args.timezone is None:
    args.timezone = 0

if args.output and not (args.extract or args.hex_dump):
    if not os.path.exists(args.output+'/ccSubSDK'):
        os.makedirs(args.output+'/ccSubSDK')

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

        if args.struct:
            if not os.path.exists(args.output + '/VBN(V1)'):
                os.makedirs(args.output + '/VBN(V1)')
            if not os.path.exists(args.output + '/VBN(V2)'):
                os.makedirs(args.output + '/VBN(V2)')
            rt0v1 = open(args.output + '/VBN(V1)/Record_type_0.csv', 'w')
            rt1v1 = open(args.output + '/VBN(V1)/Record_type_1.csv', 'w')
            rt2v1 = open(args.output + '/VBN(V1)/Record_type_2.csv', 'w')
            rt0v2 = open(args.output + '/VBN(V2)/Record_type_0.csv', 'w')
            rt1v2 = open(args.output + '/VBN(V2)/Record_type_1.csv', 'w')
            rt2v2 = open(args.output + '/VBN(V2)/Record_type_2.csv', 'w')
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

        if args.struct:
            if not os.path.exists(args.output + '/VBN(V1)'):
                os.makedirs(args.output + '/VBN(V1)')
            if not os.path.exists(args.output + '/VBN(V2)'):
                os.makedirs(args.output + '/VBN(V2)')
            rt0v1 = open(args.output + '/VBN(V1)/Record_type_0.csv', 'a')
            rt1v1 = open(args.output + '/VBN(V1)/Record_type_1.csv', 'a')
            rt2v1 = open(args.output + '/VBN(V1)/Record_type_2.csv', 'a')
            rt0v2 = open(args.output + '/VBN(V2)/Record_type_0.csv', 'a')
            rt1v2 = open(args.output + '/VBN(V2)/Record_type_1.csv', 'a')
            rt2v2 = open(args.output + '/VBN(V2)/Record_type_2.csv', 'a')

    if os.stat(timeline.name).st_size == 0:
        csv_header()

elif not (args.extract or args.hex_dump):
    if not os.path.exists('ccSubSDK'):
        os.makedirs('ccSubSDK')
    
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

        if args.struct:
            if not os.path.exists('VBN(V1)'):
                os.makedirs('VBN(V1)')
            if not os.path.exists('VBN(V2)'):
                os.makedirs('VBN(V2)')
            rt0v1 = open('VBN(V1)/Record_type_0.csv', 'w')
            rt1v1 = open('VBN(V1)/Record_type_1.csv', 'w')
            rt2v1 = open('VBN(V1)/Record_type_2.csv', 'w')
            rt0v2 = open('VBN(V2)/Record_type_0.csv', 'w')
            rt1v2 = open('VBN(V2)/Record_type_1.csv', 'w')
            rt2v2 = open('VBN(V2)/Record_type_2.csv', 'w')
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

        if args.struct:
            if not os.path.exists('VBN(V1)'):
                os.makedirs('VBN(V1)')
            if not os.path.exists('VBN(V2)'):
                os.makedirs('VBN(V2)')
            rt0v1 = open('VBN(V1)/Record_type_0.csv', 'a')
            rt1v1 = open('VBN(V1)/Record_type_1.csv', 'a')
            rt2v1 = open('VBN(V1)/Record_type_2.csv', 'a')
            rt0v2 = open('VBN(V2)/Record_type_0.csv', 'a')
            rt1v2 = open('VBN(V2)/Record_type_1.csv', 'a')
            rt2v2 = open('VBN(V2)/Record_type_2.csv', 'a')

    if os.stat(timeline.name).st_size == 0:
        csv_header()

if __name__ == "__main__":
    main()