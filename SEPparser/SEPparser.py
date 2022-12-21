import os
import sys
import re
import time
import argparse
from datetime import datetime
import ctypes
import xml.etree.ElementTree as ET
import traceback
import helpers.utils as utils
from parsers.syslog import parse_syslog
from parsers.seclog import parse_seclog
from parsers.tralog import parse_tralog
from parsers.rawlog import parse_raw
from parsers.processlog import parse_processlog
from parsers.avman import parse_avman
from parsers.av import parse_daily_av
from parsers.vbn import parse_vbn
from parsers.submissionsidx import extract_sym_submissionsidx
from parsers.ccSubSDK import extract_sym_ccSubSDK

if os.name == 'nt':
    kernel32 = ctypes.windll.kernel32
    kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 7)

submissions = ''


def csv_header():

    syslog.write('"File Name","Entry Length","Date And Time","Event ID",'
                 '"Field4","Severity","Summary","Event_Data_Size",'
                 '"Event_Source","Size_(bytes)","Location","LOG:Time",'
                 '"LOG:Event","LOG:Category","LOG:Logger","LOG:Computer",'
                 '"LOG:User","LOG:Virus","LOG:File","LOG:WantedAction1",'
                 '"LOG:WantedAction2","LOG:RealAction","LOG:Virus_Type",'
                 '"LOG:Flags","LOG:Description","LOG:ScanID","LOG:New_Ext",'
                 '"LOG:Group_ID","LOG:Event_Data1","LOG:Event_Data2_Label",'
                 '"LOG:Event_Data2","LOG:Event_Data3_Label","LOG:Event_Data3",'
                 '"LOG:Event_Data4_Label","LOG:Event_Data4",'
                 '"LOG:Event_Data5_Label","LOG:Event_Data5",'
                 '"LOG:Event_Data6_Label","LOG:Event_Data6",'
                 '"LOG:Event_Data7_Label","LOG:Event_Data7",'
                 '"LOG:Event_Data8_Label","LOG:Event_Data8",'
                 '"LOG:Event_Data9_Label","LOG:Event_Data9",'
                 '"LOG:Event_Data10_Label","LOG:Event_Data10",'
                 '"LOG:Event_Data11_Label","LOG:Event_Data11",'
                 '"LOG:Event_Data12_Label","LOG:Event_Data12",'
                 '"LOG:Event_Data13_Label","LOG:Event_Data13","LOG:VBin_ID",'
                 '"LOG:Virus_ID","LOG:Quarantine_Forward_Status","LOG:Access",'
                 '"LOG:SDN_Status","LOG:Compressed","LOG:Depth",'
                 '"LOG:Still_Infected","LOG:Def_Info",'
                 '"LOG:Def_Sequence_Number","LOG:Clean_Info",'
                 '"LOG:Delete_Info","LOG:Backup_ID","LOG:Parent","LOG:GUID",'
                 '"LOG:Client_Group","LOG:Address","LOG:Domain_Name",'
                 '"LOG:NT_Domain","LOG:MAC_Address","LOG:Version",'
                 '"LOG:Remote_Machine","LOG:Remote_Machine_IP",'
                 '"LOG:Action_1_Status","LOG:Action_2_Status",'
                 '"LOG:License_Feature_Name","LOG:License_Feature_Version",'
                 '"LOG:License_Serial_Number","LOG:License_Fulfillment_ID",'
                 '"LOG:License_Start_Date","LOG:License_Expiration_Date",'
                 '"LOG:License_LifeCycle","LOG:License_Seats_Total",'
                 '"LOG:License_Seats","LOG:Error_Code",'
                 '"LOG:License_Seats_Delta","Log:Eraser Status",'
                 '"LOG:Domain_GUID","LOG:Session_GUID","LOG:VBin_Session_ID",'
                 '"LOG:Login_Domain","LOG:Event_Data_2_1",'
                 '"LOG:Event_Data_2_Company_Name",'
                 '"LOG:Event_Data_2_Size (bytes)","LOG:Event_Data_2_Hash_Type",'
                 '"LOG:Event_Data_2_Hash","LOG:Event_Data_2_Product_Version",'
                 '"LOG:Event_Data_2_7","LOG:Event_Data_2_8",'
                 '"LOG:Event_Data_2_SONAR_Engine_Version",'
                 '"LOG:Event_Data_2_10","LOG:Event_Data_2_11",'
                 '"LOG:Event_Data_2_12","LOG:Event_Data_2_Product_Name",'
                 '"LOG:Event_Data_2_14","LOG:Event_Data_2_15",'
                 '"LOG:Event_Data_2_16","LOG:Event_Data_2_17",'
                 '"LOG:Eraser_Category_ID","LOG:Dynamic_Categoryset_ID",'
                 '"LOG:Subcategoryset_ID","LOG:Display_Name_To_Use",'
                 '"LOG:Reputation_Disposition","LOG:Reputation_Confidence",'
                 '"LOG:First_Seen","LOG:Reputation_Prevalence",'
                 '"LOG:Downloaded_URL","LOG:Creator_For_Dropper",'
                 '"LOG:CIDS_State","LOG:Behavior_Risk_Level",'
                 '"LOG:Detection_Type","LOG:Acknowledge_Text","LOG:VSIC_State",'
                 '"LOG:Scan_GUID","LOG:Scan_Duration","LOG:Scan_Start_Time",'
                 '"LOG:TargetApp","LOG:Scan_Command_GUID","LOG:Field113",'
                 '"LOG:Location","LOG:Field115","LOG:Digital_Signatures_Signer",'
                 '"LOG:Digital_Signatures_Issuer",'
                 '"LOG:Digital_Signatures_Certificate_Thumbprint",'
                 '"LOG:Field119","LOG:Digital_Signatures_Serial_Number",'
                 '"LOG:Digital_Signatures_Signing_Time","LOG:Field122",'
                 '"LOG:Field123","LOG:Field124","LOG:Field125","LOG:Field126"\n'
                 )

    seclog.write('"File Name","Entry Length","Date And Time","Event ID",'
                 '"Severity","Direction","Protocol","Remote Host","Remote Port",'
                 '"Remote MAC","Local Host","Local Port","Local MAC",'
                 '"Application","Signature ID","Signature SubID",'
                 '"Signature Name","Intrusion URL","X Intrusion Payload",'
                 '"User","User Domain","Location","Occurrences","End Time",'
                 '"Begin Time","SHA256 Hash","Description","Hack Type",'
                 '"Log Data Size","Field15","Field25","Field26",'
                 '"Remote Host IPV6","Local Host IPV6","Field34",'
                 '"Symantec Version Number","Profile Serial Number","Field37",'
                 '"MD5 Hash","URL HID Level","URL Risk Score","URL Categories",'
                 '"Data","LOG:Time","LOG:Event","LOG:Category","LOG:Logger",'
                 '"LOG:Computer","LOG:User","LOG:Virus","LOG:File",'
                 '"LOG:WantedAction1","LOG:WantedAction2","LOG:RealAction",'
                 '"LOG:Virus_Type","LOG:Flags","LOG:Description","LOG:ScanID",'
                 '"LOG:New_Ext","LOG:Group_ID","LOG:Event_Data1",'
                 '"LOG:Event_Data2_Label","LOG:Event_Data2",'
                 '"LOG:Event_Data3_Label","LOG:Event_Data3",'
                 '"LOG:Event_Data4_Label","LOG:Event_Data4",'
                 '"LOG:Event_Data5_Label","LOG:Event_Data5",'
                 '"LOG:Event_Data6_Label","LOG:Event_Data6",'
                 '"LOG:Event_Data7_Label","LOG:Event_Data7",'
                 '"LOG:Event_Data8_Label","LOG:Event_Data8",'
                 '"LOG:Event_Data9_Label","LOG:Event_Data9",'
                 '"LOG:Event_Data10_Label","LOG:Event_Data10",'
                 '"LOG:Event_Data11_Label","LOG:Event_Data11",'
                 '"LOG:Event_Data12_Label","LOG:Event_Data12",'
                 '"LOG:Event_Data13_Label","LOG:Event_Data13",'
                 '"LOG:VBin_ID","LOG:Virus_ID","LOG:Quarantine_Forward_Status",'
                 '"LOG:Access","LOG:SDN_Status","LOG:Compressed","LOG:Depth",'
                 '"LOG:Still_Infected","LOG:Def_Info","LOG:Def_Sequence_Number",'
                 '"LOG:Clean_Info","LOG:Delete_Info","LOG:Backup_ID",'
                 '"LOG:Parent","LOG:GUID","LOG:Client_Group","LOG:Address",'
                 '"LOG:Domain_Name","LOG:NT_Domain","LOG:MAC_Address",'
                 '"LOG:Version","LOG:Remote_Machine","LOG:Remote_Machine_IP",'
                 '"LOG:Action_1_Status","LOG:Action_2_Status",'
                 '"LOG:License_Feature_Name","LOG:License_Feature_Version",'
                 '"LOG:License_Serial_Number","LOG:License_Fulfillment_ID",'
                 '"LOG:License_Start_Date","LOG:License_Expiration_Date",'
                 '"LOG:License_LifeCycle","LOG:License_Seats_Total",'
                 '"LOG:License_Seats","LOG:Error_Code",'
                 '"LOG:License_Seats_Delta","Log:Eraser Status",'
                 '"LOG:Domain_GUID","LOG:Session_GUID","LOG:VBin_Session_ID",'
                 '"LOG:Login_Domain","LOG:Event_Data_2_1",'
                 '"LOG:Event_Data_2_Company_Name",'
                 '"LOG:Event_Data_2_Size (bytes)","LOG:Event_Data_2_Hash_Type",'
                 '"LOG:Event_Data_2_Hash","LOG:Event_Data_2_Product_Version",'
                 '"LOG:Event_Data_2_7","LOG:Event_Data_2_8",'
                 '"LOG:Event_Data_2_SONAR_Engine_Version","LOG:Event_Data_2_10",'
                 '"LOG:Event_Data_2_11","LOG:Event_Data_2_12",'
                 '"LOG:Event_Data_2_Product_Name","LOG:Event_Data_2_14",'
                 '"LOG:Event_Data_2_15","LOG:Event_Data_2_16",'
                 '"LOG:Event_Data_2_17","LOG:Eraser_Category_ID",'
                 '"LOG:Dynamic_Categoryset_ID","LOG:Subcategoryset_ID",'
                 '"LOG:Display_Name_To_Use","LOG:Reputation_Disposition",'
                 '"LOG:Reputation_Confidence","LOG:First_Seen",'
                 '"LOG:Reputation_Prevalence","LOG:Downloaded_URL",'
                 '"LOG:Creator_For_Dropper","LOG:CIDS_State",'
                 '"LOG:Behavior_Risk_Level","LOG:Detection_Type",'
                 '"LOG:Acknowledge_Text","LOG:VSIC_State","LOG:Scan_GUID",'
                 '"LOG:Scan_Duration","LOG:Scan_Start_Time","LOG:TargetApp",'
                 '"LOG:Scan_Command_GUID","LOG:Field113","LOG:Location",'
                 '"LOG:Field115","LOG:Digital_Signatures_Signer",'
                 '"LOG:Digital_Signatures_Issuer",'
                 '"LOG:Digital_Signatures_Certificate_Thumbprint",'
                 '"LOG:Field119","LOG:Digital_Signatures_Serial_Number",'
                 '"LOG:Digital_Signatures_Signing_Time","LOG:Field122",'
                 '"LOG:Field123","LOG:Field124","LOG:Field125","LOG:Field126"\n'
                 )

    tralog.write('"File Name","Record Length","Date and Time","Action",'
                 '"Severity","Direction","Protocol","Remote Host","Remote MAC",'
                 '"Remote Port","Local Host","Local MAC","Local Port",'
                 '"Application","User","User Domain","Location","Occurrences",'
                 '"Begin Time","End Time","Rule","Field13","Rule ID",'
                 '"Remote Host Name","Field24","Field25","Remote Host IPV6",'
                 '"Local Host IPV6","Field28","Field29","Hash:MD5",'
                 '"Hash:SHA256","Field32","Field33","Field34"\n'
                 )

    rawlog.write('"File Name","Recode Length","Date and Time","Remote Host",'
                 '"Remote Port","Local Host","Local Port","Direction","Action",'
                 '"Application","Rule","Packet Dump","Packet Decode","Event ID",'
                 '"Packet Length","Field11","Remote Host Name","Field16",'
                 '"Field17","Remote Host IPV6","Local Host IPV6","Rule ID"\n'
                 )

    processlog.write('"File Name","Record Length","Date And Time","Severity",'
                     '"Action","Test Mode","Description","API","Rule Name",'
                     '"IPV4 Address","IPV6 Address","Caller Process ID",'
                     '"Caller Process","Device Instance ID","Target",'
                     '"File Size","User","User Domain","Location","Event ID",'
                     '"Field9","Begin Time","End Time","Field15",'
                     '"Caller Return Module Name","Field21","Field22","Field26",'
                     '"Field28","Field29","Extra"\n'
                     )

    timeline.write('"File Name","Record Length","Date/Time1","Date/Time2",'
                   '"Date/Time3","Field5","LOG:Time","LOG:Event","LOG:Category",'
                   '"LOG:Logger","LOG:Computer","LOG:User","LOG:Virus",'
                   '"LOG:File","LOG:WantedAction1","LOG:WantedAction2",'
                   '"LOG:RealAction","LOG:Virus_Type","LOG:Flags",'
                   '"LOG:Description","LOG:ScanID","LOG:New_Ext","LOG:Group_ID",'
                   '"LOG:Event_Data1","LOG:Event_Data2_Label","LOG:Event_Data2",'
                   '"LOG:Event_Data3_Label","LOG:Event_Data3",'
                   '"LOG:Event_Data4_Label","LOG:Event_Data4",'
                   '"LOG:Event_Data5_Label","LOG:Event_Data5",'
                   '"LOG:Event_Data6_Label","LOG:Event_Data6",'
                   '"LOG:Event_Data7_Label","LOG:Event_Data7",'
                   '"LOG:Event_Data8_Label","LOG:Event_Data8",'
                   '"LOG:Event_Data9_Label","LOG:Event_Data9",'
                   '"LOG:Event_Data10_Label","LOG:Event_Data10",'
                   '"LOG:Event_Data11_Label","LOG:Event_Data11",'
                   '"LOG:Event_Data12_Label","LOG:Event_Data12",'
                   '"LOG:Event_Data13_Label","LOG:Event_Data13","LOG:VBin_ID",'
                   '"LOG:Virus_ID","LOG:Quarantine_Forward_Status","LOG:Access",'
                   '"LOG:SDN_Status","LOG:Compressed","LOG:Depth",'
                   '"LOG:Still_Infected","LOG:Def_Info","LOG:Def_Sequence_Number",'
                   '"LOG:Clean_Info","LOG:Delete_Info","LOG:Backup_ID",'
                   '"LOG:Parent","LOG:GUID","LOG:Client_Group","LOG:Address",'
                   '"LOG:Domain_Name","LOG:NT_Domain","LOG:MAC_Address",'
                   '"LOG:Version","LOG:Remote_Machine","LOG:Remote_Machine_IP",'
                   '"LOG:Action_1_Status","LOG:Action_2_Status",'
                   '"LOG:License_Feature_Name","LOG:License_Feature_Version",'
                   '"LOG:License_Serial_Number","LOG:License_Fulfillment_ID",'
                   '"LOG:License_Start_Date","LOG:License_Expiration_Date",'
                   '"LOG:License_LifeCycle","LOG:License_Seats_Total",'
                   '"LOG:License_Seats","LOG:Error_Code","LOG:License_Seats_Delta",'
                   '"Log:Eraser Status","LOG:Domain_GUID","LOG:Session_GUID",'
                   '"LOG:VBin_Session_ID","LOG:Login_Domain","LOG:Event_Data_2_1",'
                   '"LOG:Event_Data_2_Company_Name",'
                   '"LOG:Event_Data_2_Size (bytes)","LOG:Event_Data_2_Hash_Type",'
                   '"LOG:Event_Data_2_Hash","LOG:Event_Data_2_Product_Version",'
                   '"LOG:Event_Data_2_7","LOG:Event_Data_2_8",'
                   '"LOG:Event_Data_2_SONAR_Engine_Version","LOG:Event_Data_2_10",'
                   '"LOG:Event_Data_2_11","LOG:Event_Data_2_12",'
                   '"LOG:Event_Data_2_Product_Name","LOG:Event_Data_2_14",'
                   '"LOG:Event_Data_2_15","LOG:Event_Data_2_16",'
                   '"LOG:Event_Data_2_17","LOG:Eraser_Category_ID",'
                   '"LOG:Dynamic_Categoryset_ID","LOG:Subcategoryset_ID",'
                   '"LOG:Display_Name_To_Use","LOG:Reputation_Disposition",'
                   '"LOG:Reputation_Confidence","LOG:First_Seen",'
                   '"LOG:Reputation_Prevalence","LOG:Downloaded_URL",'
                   '"LOG:Creator_For_Dropper","LOG:CIDS_State",'
                   '"LOG:Behavior_Risk_Level","LOG:Detection_Type",'
                   '"LOG:Acknowledge_Text","LOG:VSIC_State","LOG:Scan_GUID",'
                   '"LOG:Scan_Duration","LOG:Scan_Start_Time","LOG:TargetApp",'
                   '"LOG:Scan_Command_GUID","LOG:Field113","LOG:Location",'
                   '"LOG:Field115","LOG:Digital_Signatures_Signer",'
                   '"LOG:Digital_Signatures_Issuer",'
                   '"LOG:Digital_Signatures_Certificate_Thumbprint",'
                   '"LOG:Field119","LOG:Digital_Signatures_Serial_Number",'
                   '"LOG:Digital_Signatures_Signing_Time","LOG:Field122",'
                   '"LOG:Field123","LOG:Field124","LOG:Field125","LOG:Field126"\n'
                   )

    tamperProtect.write('"File Name","Computer","User","Action Taken",'
                        '"Object Type","Event","Actor","Target",'
                        '"Target Process","Date and Time"\n'
                        )

    quarantine.write('"File Name","Virus","Description","Record ID",'
                     '"Creation Date 1 UTC","Access Date 1 UTC",'
                     '"Modify Date 1 UTC","VBin Time 1 UTC","Storage Name",'
                     '"Storage Instance ID","Storage Key",'
                     '"Quarantine Data Size 1","Creation Date 2 UTC",'
                     '"Access Date 2 UTC","Modify Date 2 UTC","VBin Time 2 UTC",'
                     '"Unique ID","Record Type","Quarantine Session ID",'
                     '"Remediation Type","Wide Description","SHA1","Actual SHA1",'
                     '"Actual MD5","Actual SHA256","Quarantine Data Size 2",'
                     '"SID","SDDL","Quarantine Data Size 3","Detection Digest",'
                     '"GUID","QData Length","Unknown Header","Attribute Type",'
                     '"Attribute Data","Extra Data","LOG:Time","LOG:Event",'
                     '"LOG:Category","LOG:Logger","LOG:Computer","LOG:User",'
                     '"LOG:Virus","LOG:File","LOG:WantedAction1",'
                     '"LOG:WantedAction2","LOG:RealAction","LOG:Virus_Type",'
                     '"LOG:Flags","LOG:Description","LOG:ScanID","LOG:New_Ext",'
                     '"LOG:Group_ID","LOG:Event_Data1","LOG:Event_Data2_Label",'
                     '"LOG:Event_Data2","LOG:Event_Data3_Label",'
                     '"LOG:Event_Data3","LOG:Event_Data4_Label",'
                     '"LOG:Event_Data4","LOG:Event_Data5_Label",'
                     '"LOG:Event_Data5","LOG:Event_Data6_Label",'
                     '"LOG:Event_Data6","LOG:Event_Data7_Label",'
                     '"LOG:Event_Data7","LOG:Event_Data8_Label",'
                     '"LOG:Event_Data8","LOG:Event_Data9_Label",'
                     '"LOG:Event_Data9","LOG:Event_Data10_Label",'
                     '"LOG:Event_Data10","LOG:Event_Data11_Label",'
                     '"LOG:Event_Data11","LOG:Event_Data12_Label",'
                     '"LOG:Event_Data12","LOG:Event_Data13_Label",'
                     '"LOG:Event_Data13","LOG:VBin_ID","LOG:Virus_ID",'
                     '"LOG:Quarantine_Forward_Status","LOG:Access",'
                     '"LOG:SDN_Status","LOG:Compressed","LOG:Depth",'
                     '"LOG:Still_Infected","LOG:Def_Info",'
                     '"LOG:Def_Sequence_Number","LOG:Clean_Info",'
                     '"LOG:Delete_Info","LOG:Backup_ID","LOG:Parent","LOG:GUID",'
                     '"LOG:Client_Group","LOG:Address","LOG:Domain_Name",'
                     '"LOG:NT_Domain","LOG:MAC_Address","LOG:Version",'
                     '"LOG:Remote_Machine","LOG:Remote_Machine_IP",'
                     '"LOG:Action_1_Status","LOG:Action_2_Status",'
                     '"LOG:License_Feature_Name","LOG:License_Feature_Version",'
                     '"LOG:License_Serial_Number","LOG:License_Fulfillment_ID",'
                     '"LOG:License_Start_Date","LOG:License_Expiration_Date",'
                     '"LOG:License_LifeCycle","LOG:License_Seats_Total",'
                     '"LOG:License_Seats","LOG:Error_Code",'
                     '"LOG:License_Seats_Delta","Log:Eraser Status",'
                     '"LOG:Domain_GUID","LOG:Session_GUID","LOG:VBin_Session_ID",'
                     '"LOG:Login_Domain","LOG:Event_Data_2_1",'
                     '"LOG:Event_Data_2_Company_Name",'
                     '"LOG:Event_Data_2_Size (bytes)",'
                     '"LOG:Event_Data_2_Hash_Type","LOG:Event_Data_2_Hash",'
                     '"LOG:Event_Data_2_Product_Version","LOG:Event_Data_2_7",'
                     '"LOG:Event_Data_2_8","LOG:Event_Data_2_SONAR_Engine_Version",'
                     '"LOG:Event_Data_2_10","LOG:Event_Data_2_11",'
                     '"LOG:Event_Data_2_12","LOG:Event_Data_2_Product_Name",'
                     '"LOG:Event_Data_2_14","LOG:Event_Data_2_15",'
                     '"LOG:Event_Data_2_16","LOG:Event_Data_2_17",'
                     '"LOG:Eraser_Category_ID","LOG:Dynamic_Categoryset_ID",'
                     '"LOG:Subcategoryset_ID","LOG:Display_Name_To_Use",'
                     '"LOG:Reputation_Disposition","LOG:Reputation_Confidence",'
                     '"LOG:First_Seen","LOG:Reputation_Prevalence",'
                     '"LOG:Downloaded_URL","LOG:Creator_For_Dropper",'
                     '"LOG:CIDS_State","LOG:Behavior_Risk_Level",'
                     '"LOG:Detection_Type","LOG:Acknowledge_Text",'
                     '"LOG:VSIC_State","LOG:Scan_GUID","LOG:Scan_Duration",'
                     '"LOG:Scan_Start_Time","LOG:TargetApp",'
                     '"LOG:Scan_Command_GUID","LOG:Field113","LOG:Location",'
                     '"LOG:Field115","LOG:Digital_Signatures_Signer",'
                     '"LOG:Digital_Signatures_Issuer",'
                     '"LOG:Digital_Signatures_Certificate_Thumbprint",'
                     '"LOG:Field119","LOG:Digital_Signatures_Serial_Number",'
                     '"LOG:Digital_Signatures_Signing_Time","LOG:Field122",'
                     '"LOG:Field123","LOG:Field124","LOG:Field125","LOG:Field126"\n'
                     )

    settings.write('"Log Name","Max Log Size","# of Logs",'
                   '"Running Total of Logs","Max Log Days","Field3","Field5",'
                   '"Field6"\n'
                   )

    submissions.write('"Index","Field1","Start of Index","Start of last Index",'
                      '"Container Length","Data Length","Field6","GUID","0x5","0x9","MD5","Description","Report","Component Name","MD5-2","SHA256","File Name"\n'
                      )


__author__ = "Brian Maloney"
__version__ = "2021.05.03"
__email__ = "bmmaloney97@gmail.com"


class Logger(object):
    def __init__(self):
        self.terminal = sys.stdout
        self.log = open(logfile, "w")

    def write(self, message):
        self.terminal.write(message)
        ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
        self.log.write(ansi_escape.sub('', message))

    def flush(self):
        # this flush method is needed for python 3 compatibility.
        # this handles the flush command by doing nothing.
        # you might want to specify some extra behavior here.
        pass


def parse_header(f):

    headersize = len(f.readline())

    if headersize == 0:
        print(f'\033[1;33mSkipping {f.name}. Unknown File Type. \033[1;0m\n')
        return 11, 0, 0, 1, 0, 0, 0, 0

    f.seek(0)
    sheader = f.read(16).hex()

    if sheader[0:16] == '3216144c01000000':
        return 9, 0, 0, 1, 0, 0, 0, 0

    if re.search('\{[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\}$', f.name, re.IGNORECASE):
        return 10, 0, 0, 1, 0, 0, 0, 0

    f.seek(0)

    if headersize == 55:
        logType = 5
        maxSize = utils.read_unpack_hex(f, 0, 8)
        field3 = utils.read_unpack_hex(f, 9, 8)
        cLogEntries = utils.read_unpack_hex(f, 18, 8)
        field5 = utils.read_unpack_hex(f, 27, 8)
        field6 = utils.read_unpack_hex(f, 36, 8)
        tLogEntries = 'N\A'
        maxDays = utils.read_unpack_hex(f, 45, 8)

        return logType, maxSize, field3, cLogEntries, field5, field6, tLogEntries, maxDays

    if headersize == 72:
        logType = utils.read_unpack_hex(f, 0, 8)
        maxSize = utils.read_unpack_hex(f, 9, 8)
        field3 = utils.read_unpack_hex(f, 18, 8)
        cLogEntries = utils.read_unpack_hex(f, 27, 8)
        field5 = utils.read_unpack_hex(f, 36, 8)
        field6 = 'N\A'
        tLogEntries = utils.read_unpack_hex(f, 45, 16)
        maxDays = utils.read_unpack_hex(f, 62, 8)

        return logType, maxSize, field3, cLogEntries, field5, field6, tLogEntries, maxDays

    try:
        utils.from_symantec_time(f.readline().split(b',')[0].decode("utf-8", "ignore"), 0)
        return 6, 0, 0, 1, 0, 0, 0, 0

    except:
        pass

    try:
        f.seek(388, 0)
        utils.from_symantec_time(f.read(2048).split(b',')[0].decode("utf-8", "ignore"), 0)
        return 7, 0, 0, 1, 0, 0, 0, 0

    except:
        pass

    try:
        f.seek(4100, 0)
        utils.from_symantec_time(f.read(2048).split(b',')[0].decode("utf-8", "ignore"), 0)
        return 8, 0, 0, 1, 0, 0, 0, 0

    except:
        print(f'\033[1;33mSkipping {f.name}. Unknown File Type. \033[1;0m\n')
        return 11, 0, 0, 1, 0, 0, 0, 0


def utc_offset(_):
    tree = ET.parse(_)
    root = tree.getroot()

    for SSAUTC in root.iter('SSAUTC'):
        utc = SSAUTC.get('Bias')

    return int(utc)


banner = '''
\033[1;93m____________\033[1;0m
\033[1;93m|   |  |   |\033[1;0m
\033[1;93m|   |  |   |\033[1;97m   ____  _____ ____
\033[1;93m|   |  |   |\033[1;97m  / ___|| ____|  _ \ _ __   __ _ _ __ ___  ___ _ __
\033[1;93m|   |  |\033[1;92m___\033[1;93m|\033[1;97m  \___ \|  _| | |_) | '_ \ / _` | '__/ __|/ _ \ '__|
\033[1;93m \  |  \033[1;92m/ _ \ \033[1;97m  ___) | |___|  __/| |_) | (_| | |  \__ \  __/ |
\033[1;93m  \ | \033[1;92m| (_) |\033[1;97m |____/|_____|_|   | .__/ \__,_|_|  |___/\___|_| v{}
\033[1;93m    \  \033[1;92m\___/\033[1;97m                    |_|
\033[1;93m     \/\033[1;0m      by @bmmaloney97
'''.format(__version__)


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
                        s, t = parse_syslog(f, cLogEntries)
                        syslog.write(s)
                        timeline.write(t)

                    if logType == 1:
                        s, t = parse_seclog(f, cLogEntries)
                        seclog.write(s)
                        timeline.write(t)

                    if logType == 2:
                        t = parse_tralog(f, cLogEntries)
                        tralog.write(t)

                    if logType == 3:
                        parse_raw(f, cLogEntries, rawlog, packet, args.hex_dump)

                    if logType == 4:
                        # can have more fields after ipv6
                        p = parse_processlog(f, cLogEntries)
                        processlog.write(p)

                    if logType == 5:
                        t, tp = parse_avman(f, cLogEntries)
                        timeline.write(t)
                        tamperProtect.write(tp)

                    if logType == 6:
                        t, tp = parse_daily_av(f, logType, args.timezone)
                        timeline.write(t)
                        tamperProtect.write(tp)

                    if logType == 7:
                        q = parse_vbn(f, logType, args.timezone, args.hex_dump, args.quarantine_dump, args.hash_file, args.extract, args.output)

                        if not (args.extract or args.hex_dump):
                            quarantine.write(q)
                            t, tp = parse_daily_av(f, logType, args.timezone)
                            timeline.write(t)
                            tamperProtect.write(tp)

                    if logType == 8:
                        q = parse_vbn(f, logType, args.timezone, args.hex_dump, args.quarantine_dump, args.hash_file, args.extract, args.output)

                        if not (args.extract or args.hex_dump):
                            quarantine.write(q)
                            t, tp = parse_daily_av(f, logType, args.timezone)
                            timeline.write(t)
                            tamperProtect.write(tp)

                    if logType == 9:
                        not_found = extract_sym_submissionsidx(f, submissions, args.index, args.hex_dump, args.output, filenames)
                        if not_found:
                            print(f'\n\n\033[1;33mUnable to locate submission {args.index}.\033[1;0m\n')

                    if logType == 10:
                        extract_sym_ccSubSDK(f, args.hex_dump, args.extract_blob, args.output)

                    if logType == 11:
                        continue

                    print(f'\033[1;32mFinished parsing {filename} \033[1;0m\n')

                except Exception as e:
                    print(f'\033[1;31mProblem parsing {filename}: {e} \033[1;0m\n')
                    if args.verbose:
                        traceback.print_exc()
                        input()
                    continue

        except Exception as e:
            print(f'\033[1;33mSkipping {filename}. \033[1;31m{e}\033[1;0m\n')
            if args.verbose:
                traceback.print_exc()
                input()

    print(f'\033[1;37mProcessed {len(filenames)} file(s) in {format((time.time() - start), ".4f")} seconds \033[1;0m')
    sys.exit()


print(banner)
start = time.time()
parser = argparse.ArgumentParser()
parser.add_argument("-f", "--file", help="File to be parsed")
parser.add_argument("-d", "--dir", help="Directory to be parsed")
parser.add_argument("-e", "--extract", help="Extract quarantine file from VBN if present.", action="store_true")
parser.add_argument("-eb", "--extract-blob", help="Extract potential binary blobs from ccSubSDK", action="store_true")
parser.add_argument("-hd", "--hex-dump", help="Dump hex output of VBN to screen.", action="store_true")
parser.add_argument("-i", "--index", help="Dump hex output of index in submissions.idx.")
parser.add_argument("-qd", "--quarantine-dump", help="Dump hex output of quarantine to screen.", action="store_true")
parser.add_argument("-hf", "--hash-file", help="Hash quarantine data to see if it matches recorded hash.", action="store_true")
parser.add_argument("-o", "--output", help="Directory to output files to. Default is current directory.", default=".")
parser.add_argument("-a", "--append", help="Append to output files.", action="store_true")
parser.add_argument("-r", "--registrationInfo", help="Path to registrationInfo.xml")
parser.add_argument("-tz", "--timezone", type=int, help="UTC offset")
parser.add_argument("-k", "--kape", help="Kape mode", action="store_true")
parser.add_argument("-l", "--log", help="Save console output to log", action="store_true")
parser.add_argument("-v", "--verbose", help="More verbose errors", action="store_true")

if len(sys.argv) == 1:
    parser.print_help()
    parser.exit()

args = parser.parse_args()

if not os.path.exists(args.output):
    os.makedirs(args.output)

logfile = args.output + "/" + datetime.now().strftime("%Y-%m-%dT%H%M%S_console.log")

if args.log:
    sys.stdout = Logger()

regex = re.compile(r'\\Symantec Endpoint Protection\\(Logs|.*\\Data\\Logs|.*\\Data\\Quarantine|.*\\Data\\CmnClnt\\ccSubSDK)')
filenames = []

if (args.hex_dump or args.extract) and not args.file:
    print("\n\033[1;31m-e, --extract and/or -hd, --hexdump can only be used with -f, --file.\033[1;0m\n")
    sys.exit()

if args.hex_dump and (args.extract_blob or args.quarantine_dump or args.extract):
    print("\n\033[1;31m-e, --extract and/or -eb, --extract-blob and/or -qd, --quaratine-dump cannot be used with -hd, --hex-dump.\033[1;0m\n")
    sys.exit()

if args.index and not args.hex_dump:
    print("\n\033[1;31m-i, --index can only be used with -hd, --hexdump.\033[1;0m\n")
    sys.exit()

if args.registrationInfo:
    try:
        print('\033[1;36mAttempting to apply timezone offset.\n \033[1;0m')
        args.timezone = utc_offset(args.registrationInfo)
        print(f'\033[1;32mTimezone offset of {args.timezone} applied successfully. \033[1;0m\n')

    except Exception as e:
        print(f'\033[1;31mUnable to apply offset. Timestamps will not be adjusted. {e}\033[1;0m\n')
        pass

if (args.kape or args.dir) and not args.file:
    print('\nSearching for Symantec logs.\n')
    rootDir = '/'

    if args.dir:
        rootDir = args.dir

    for path, subdirs, files in os.walk(rootDir):
        if args.kape:
            if 'registrationInfo.xml' in files:
                pass

            elif not regex.findall(path):
                continue

        for name in files:
            if args.timezone is None and (args.registrationInfo or name == 'registrationInfo.xml'):
                reginfo = os.path.join(path, name)

                if args.registrationInfo:
                    reginfo = args.registrationInfo

                try:
                    print(f'\033[1;36m{reginfo} found. Attempting to apply timezone offset.\n \033[1;0m')
                    args.timezone = utc_offset(reginfo)
                    print(f'\033[1;32mTimezone offset of {args.timezone} applied successfully. \033[1;0m\n')

                except Exception as e:
                    print(f'\033[1;31mUnable to apply offset. Timestamps will not be adjusted. {e}\033[1;0m\n')

            filenames.append(os.path.join(path, name))

    if not filenames:
        print('No Symantec logs found.')
        sys.exit()

if args.file:
    filenames = [args.file]

if args.timezone is None:
    args.timezone = 0

if args.output and not (args.extract or args.hex_dump):
    if not os.path.exists(args.output+'/ccSubSDK'):
        os.makedirs(args.output+'/ccSubSDK')

    if not args.append:
        syslog = open(args.output + '/Symantec_Client_Management_System_Log.csv', 'w', encoding='utf-8')
        seclog = open(args.output + '/Symantec_Client_Management_Security_Log.csv', 'w', encoding='utf-8')
        tralog = open(args.output + '/Symantec_Network_and_Host_Exploit_Mitigation_Traffic_Log.csv', 'w', encoding='utf-8')
        rawlog = open(args.output + '/Symantec_Network_and_Host_Exploit_Mitigation_Packet_Log.csv', 'w', encoding='utf-8')
        processlog = open(args.output + '/Symantec_Client_Management_Control_Log.csv', 'w', encoding='utf-8')
        timeline = open(args.output + '/Symantec_Timeline.csv', 'w', encoding='utf-8')
        packet = open(args.output + '/packets.txt', 'w', encoding='utf-8')
        tamperProtect = open(args.output + '/Symantec_Client_Management_Tamper_Protect_Log.csv', 'w', encoding='utf-8')
        quarantine = open(args.output + '/quarantine.csv', 'w', encoding='utf-8')
        settings = open(args.output + '/settings.csv', 'w', encoding='utf-8')
        submissions = open(args.output + '/ccSubSDK/submissions.csv', 'w', encoding='utf-8')

    else:
        syslog = open(args.output + '/Symantec_Client_Management_System_Log.csv', 'a', encoding='utf-8')
        seclog = open(args.output + '/Symantec_Client_Management_Security_Log.csv', 'a', encoding='utf-8')
        tralog = open(args.output + '/Symantec_Network_and_Host_Exploit_Mitigation_Traffic_Log.csv', 'a', encoding='utf-8')
        rawlog = open(args.output + '/Symantec_Network_and_Host_Exploit_Mitigation_Packet_Log.csv', 'a', encoding='utf-8')
        processlog = open(args.output + '/Symantec_Client_Management_Control_Log.csv', 'a', encoding='utf-8')
        timeline = open(args.output + '/Symantec_Timeline.csv', 'a', encoding='utf-8')
        packet = open(args.output + '/packets.txt', 'a', encoding='utf-8')
        tamperProtect = open(args.output + '/Symantec_Client_Management_Tamper_Protect_Log.csv', 'a', encoding='utf-8')
        quarantine = open(args.output + '/quarantine.csv', 'a', encoding='utf-8')
        settings = open(args.output + '/settings.csv', 'a', encoding='utf-8')
        submissions = open(args.output + '/ccSubSDK/submissions.csv', 'a', encoding='utf-8')

    if os.stat(timeline.name).st_size == 0:
        csv_header()

if __name__ == "__main__":
    main()
