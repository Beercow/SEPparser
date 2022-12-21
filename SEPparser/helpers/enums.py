'''Log Line'''
# info from https://knowledge.broadcom.com/external/article?legacyId=TECH100099
# unless otherwise noted
event = {
         1: "IS_ALERT",
         2: "SCAN_STOP",
         3: "SCAN_START",
         4: "PATTERN_UPDATE",
         5: "INFECTION",
         6: "FILE_NOTOPEN",
         7: "LOAD_PATTERN",
         8: "MESSAGE_INFO",
         9: "MESSAGE_ERROR",
         10: "CHECKSUM",
         11: "TRAP",
         12: "CONFIG_CHANGE",
         13: "SHUTDOWN",
         14: "STARTUP",
         16: "PATTERN_DOWNLOAD",
         17: "TOO_MANY_VIRUSES",
         18: "FWD_TO_QSERVER",
         19: "SCANDLVR",
         20: "BACKUP",
         21: "SCAN_ABORT",
         22: "RTS_LOAD_ERROR",
         23: "RTS_LOAD",
         24: "RTS_UNLOAD",
         25: "REMOVE_CLIENT",
         26: "SCAN_DELAYED",
         27: "SCAN_RESTART",
         28: "ADD_SAVROAMCLIENT_TOSERVER",
         29: "REMOVE_SAVROAMCLIENT_FROMSERVER",
         30: "LICENSE_WARNING",
         31: "LICENSE_ERROR",
         32: "LICENSE_GRACE",
         33: "UNAUTHORIZED_COMM",
         34: "LOG:FWD_THRD_ERR",
         35: "LICENSE_INSTALLED",
         36: "LICENSE_ALLOCATED",
         37: "LICENSE_OK",
         38: "LICENSE_DEALLOCATED",
         39: "BAD_DEFS_ROLLBACK",
         40: "BAD_DEFS_UNPROTECTED",
         41: "SAV_PROVIDER_PARSING_ERROR",
         42: "RTS_ERROR",
         43: "COMPLIANCE_FAIL",
         44: "COMPLIANCE_SUCCESS",
         45: "SECURITY_SYMPROTECT_POLICYVIOLATION",
         46: "ANOMALY_START",
         47: "DETECTION_ACTION_TAKEN",
         48: "REMEDIATION_ACTION_PENDING",
         49: "REMEDIATION_ACTION_FAILED",
         50: "REMEDIATION_ACTION_SUCCESSFUL",
         51: "ANOMALY_FINISH",
         52: "COMMS_LOGIN_FAILED",
         53: "COMMS_LOGIN_SUCCESS",
         54: "COMMS_UNAUTHORIZED_COMM",
         55: "CLIENT_INSTALL_AV",
         56: "CLIENT_INSTALL_FW",
         57: "CLIENT_UNINSTALL",
         58: "CLIENT_UNINSTALL_ROLLBACK",
         59: "COMMS_SERVER_GROUP_ROOT_CERT_ISSUE",
         60: "COMMS_SERVER_CERT_ISSUE",
         61: "COMMS_TRUSTED_ROOT_CHANGE",
         62: "COMMS_SERVER_CERT_STARTUP_FAILED",
         63: "CLIENT_CHECKIN",
         64: "CLIENT_NO_CHECKIN",
         65: "SCAN_SUSPENDED",
         66: "SCAN_RESUMED",
         67: "SCAN_DURATION_INSUFFICIENT",
         68: "CLIENT_MOVE",
         69: "SCAN_FAILED_ENHANCED",
         70: "COMPLIANCE_FAILEDAUDIT",
         71: "HEUR_THREAT_NOW_WHITELISTED",
         72: "INTERESTING_PROCESS_DETECTED_START",
         73: "LOAD_ERROR_BASH",
         74: "LOAD_ERROR_BASH_DEFINITIONS",
         75: "INTERESTING_PROCESS_DETECTED_FINISH",
         76: "BASH_NOT_SUPPORTED_FOR_OS",
         77: "HEUR_THREAT_NOW_KNOWN",
         78: "DISABLE_BASH",
         79: "ENABLE_BASH",
         80: "DEFS_LOAD_FAILED",
         81: "LOCALREP_CACHE_SERVER_ERROR",
         82: "REPUTATION_CHECK_TIMEOUT",
         83: "SYMEPSECFILTER_DRIVER_ERROR",
         84: "VSIC_COMMUNICATION_WARNING",
         85: "VSIC_COMMUNICATION_RESTORED",
         86: "ELAM_LOAD_FAILED",
         87: "ELAM_INVALID_OS",
         88: "ELAM_ENABLE",
         89: "ELAM_DISABLE",
         90: "ELAM_BAD",
         91: "ELAM_BAD_REPORTED_AS_UNKNOWN",
         92: "DISABLE_SYMPROTECT",
         93: "ENABLE_SYMPROTECT",
         94: "NETSEC_EOC_PARSE_FAILED"
        }

category = {
            1: "Infection",
            2: "Summary",
            3: "Pattern",
            4: "Security"
           }

logger = {
          0: "Scheduled",
          1: "Manual",
          2: "Real_Time",
          3: "Integrity_Shield",
          6: "Console",
          7: "VPDOWN",
          8: "System",
          9: "Startup",
          10: "Idle",
          11: "DefWatch",
          12: "Licensing",
          13: "Manual_Quarantine",
          14: "SymProtect",
          15: "Reboot_Processing",
          16: "Bash",
          17: "SymElam",
          18: "PowerEraser",
          19: "EOCScan",
          100: "LOCAL_END",
          101: "Client",
          102: "Forewarded",
          256: "Transport_Client"
         }

ll_action = {
          4294967295: "Invalid",
          1: "Quarantine",
          2: "Rename",
          3: "Delete",
          4: "Leave Alone",
          5: "Clean",
          6: "Remove Macros",
          7: "Save file as...",
          8: "Send to backend",
          9: "Restore from Quarantine",
          10: "Rename Back (unused)",
          11: "Undo Action",
          12: "Error",
          13: "Backup to quarantine (backup view)",
          14: "Pending Analysis",
          15: "Partial Analysis",
          16: "Terminate Process Required",
          17: "Exclude from Scanning",
          18: "Reboot Processing",
          19: "Clean by Deletion",
          20: "Access Denied",
          21: "TERMINATE PROCESS ONLY",
          22: "NO REPAIR",
          23: "FAIL",
          24: "RUN POWERTOOL",
          25: "NO REPAIR POWERTOOL",
          98: "Suspicious",
          99: "Details Pending",
          100: "IDS Block",
          101: "Firewall violation",
          102: "Allowed by User",
          110: "INTERESTING PROCESS CAL",
          111: "INTERESTING PROCESS DETECTED",
          200: "Attachment Stripped",
          500: "Not Applicable",
          1000: "INTERESTING PROCESS HASHED DETECTED",
          1001: "DNS HOST FILE EXCEPTOION"
         }

virus_type = {
              48: "Heuristic",
              64: "Reputation",
              80: "Hack Tools",
              96: "Spyware",
              112: "Trackware",
              128: "Dialers",
              144: "Remote Access",
              160: "Adware",
              176: "Joke Programs",
              224: "Heuristic Application",
             }


# need reference
remediation_type_desc = {
                         0: "",
                         2000: "Registry",
                         2001: "File",
                         2002: "Process",
                         2003: "Batch File",
                         2004: "INI File",
                         2005: "Service",
                         2006: "Infected File",
                         2007: "COM Object",
                         2008: "Host File Entry",
                         2009: "Directory",
                         2010: "Layered Service Provider",
                         2011: "Internet Browser Cache"
                        }

# Compairing log to gui
event_301 = {
             1: 'File","Create',
             2: 'File","Delete',
             3: 'File","Open',
             6: 'Directory","Create',
             7: 'Directory","Delete',
             14: 'Registry Key","Create',
             15: 'Registry Key","Delete',
             16: 'Registry Value","Delete',
             17: 'Registry Value","Set',
             18: 'Registry Key","Rename',
             19: 'Registry Key","Set Security',
             45: 'File","Set Security',
             46: 'Directory","Set Security',
             55: 'Process","Open',
             56: 'Process","Duplicate',
             58: 'Thread","Duplicate'
            }

# need reference
quarantine_forward_status = {
                             0: "None",
                             1: "Failed",
                             2: "OK"
                            }
# need reference
yn = {
      0: "No",
      1: "Yes"
     }

# need reference
clean_info = {
              0: "Cleanable",
              1: "No Clean Pattern",
              2: "Not Cleanable"
             }

# need reference
delete_info = {
               4: "Deletable",
               5: "Not Deletable"
              }

eraser_status = {
                 0: "Success",
                 1: "Reboot Required",
                 2: "Nothing To Do",
                 3: "Repaired",
                 4: "Deleted",
                 5: "False",
                 6: "Abort",
                 7: "Continue",
                 8: "Service Not Stopped",
                 9: "Application Heuristic Scan Failure",
                 10: "Cannot Remediate",
                 11: "Whitelist Failure",
                 12: "Driver Failure",
                 # 4x entries present in original macro
                 13: "Reserved01",
                 # 13: "Commercial Application List Failure",
                 # 13: "Application Heuristic Scan Invalid OS",
                 # 13: "Content Manager Data Error",
                 999: "Leave Alone",
                 1000: "Generic Failure",
                 1001: "Out Of Memory",
                 1002: "Not Initialized",
                 1003: "Invalid Argument",
                 1004: "Insufficient Buffer",
                 1005: "Decryption Error",
                 1006: "File Not Found",
                 1007: "Out Of Range",
                 1008: "COM Error",
                 1009: "Partial Failure",
                 1010: "Bad Definitions",
                 1011: "Invalid Command",
                 1012: "No Interface",
                 1013: "RSA Error",
                 1014: "Path Not Empty",
                 1015: "Invalid Path",
                 1016: "Path Not Empty",
                 1017: "File Still Present",
                 1018: "Invalid OS",
                 1019: "Not Implemented",
                 1020: "Access Denied",
                 1021: "Directory Still Present",
                 1022: "Inconsistent State",
                 1023: "Timeout",
                 1024: "Action Pending",
                 1025: "Volume Write Protected",
                 1026: "Not Reparse Point",
                 1027: "File Exists",
                 1028: "Target Protected",
                 1029: "Disk Full",
                 1030: "Shutdown In Progress",
                 1031: "Media Error",
                 1032: "Network Defs Error"
                 }

hash_type = {
             0: "MD5",
             1: "SHA-1",
             2: "SHA-256"
            }

eraser_category_id = {
                      1: "HeuristicTrojanWorm",
                      2: "HeuristicKeyLogger",
                      100: "CommercialRemoteControl",
                      101: "CommercialKeyLogger",
                      200: "Cookie",
                      300: "Shields"
                      }

dynamic_categoryset_id = {
                          1: "MALWARE",
                          2: "SECURITY_RISK",
                          3: "POTENTIALLY_UNWANTED_APPLICATIONS",
                          4: "EXPERIMENTAL_HEURISTIC",
                          5: "LEGACY_VIRAL",
                          6: "LEGACY_NON_VIRAL",
                          7: "CATEGORY_CRIMEWARE",
                          8: "ADVANCED_HEURISTICS",
                          9: "REPUTATION_BACKED_ADVANCED_HEURISTICS",
                          10: "PREVALENCE_BACKED_ADVANCED_HEURISTICS"
                          }

display_name = {
                0: "Application Name",
                1: "VID Virus Name"
               }

reputation_disposition = {
                          0: "Good",
                          1: "Bad",
                          127: "Unknown"
                          }

# https://techdocs.broadcom.com/content/dam/broadcom/techdocs/symantec-security-software/endpoint-security-and-management/endpoint-protection/generated-pdfs/Database_Schema_Reference_SEP14-3-RU2.zip
reputation_confidence = {
                         range(0, 10): "Unknown",
                         range(10, 25): "Low",
                         range(25, 65): "Medium",
                         range(65, 100): "High",
                         range(100, 200): "Extremely High"
                        }

# https://techdocs.broadcom.com/content/dam/broadcom/techdocs/symantec-security-software/endpoint-security-and-management/endpoint-protection/generated-pdfs/Database_Schema_Reference_SEP14-3-RU2.zip
reputation_prevalence = {
                         range(0, 1): "Unknown",
                         range(1, 51): "Very Low",
                         range(51, 101): "Low",
                         range(101, 151): "Moderate",
                         range(151, 201): "High",
                         range(201, 256): "Very High",
                         range(256, 356): "Extremely High"
                        }

cids_state = {
              0: "Disabled",
              1: "On",
              2: "Not Installed",
              3: "Disabled By Policy",
              4: "Malfunctioning",
              5: "Disabled As Unlicensed",
              127: "Status Not Reported"
             }

detection_type = {
                  0: "Traditional",
                  1: "Heuristic"
                 }

vsic_state = {
              0: "Off",
              1: "On",
              '': "Failed"
             }

targetapp_type = {
                  0: "Normal",
                  1: "Metro"
                 }

'''syslog.log'''
syslog_severity = {
            0: "Information",
            1: "Warning",
            2: "Error",
            3: "Fatal"
           }

syslog_event_id = {
            # Installation events Possible values are:
            '12070001': "Internal error",
            '12070101': "Install complete",
            '12070102': "Restart recommended",
            '12070103': "Restart required",
            '12070104': "Installation failed",
            '12070105': "Uninstallation complete",
            '12070106': "Uninstallation failed",
            '12071037': "Symantec Endpoint Protection installed",
            '12071038': "Symantec Firewall installed",
            '12071039': "Uninstall",
            '1207103A': "Uninstall rolled-back",
            # Service events Possible values are:
            '12070201': "Service starting",
            '12070202': "Service started",
            '12070203': "Service start failure",
            '12070204': "Service stopped",
            '12070205': "Service stop failure",
            '1207021A': "Attempt to stop service",
            # Configuration events Possible values are:
            '12070206': "Config import complete",
            '12070207': "Config import error",
            '12070208': "Config export complete",
            '12070209': "Config export error",
            # Host Integrity events Possible values are:
            '12070210': "Host Integrity disabled",
            '12070211': "Host Integrity enabled",
            '12070220': "NAP integration enabled",
            # Import events Possible values are:
            '12070214': "Successfully imported advanced rule",
            '12070215': "Failed to import advanced rule",
            '12070216': "Successfully exported advanced rule",
            '12070217': "Failed to export advanced rule",
            '1207021B': "Imported sylink",
            # Client events Possible values are:
            '12070218': "Client Engine enabled",
            '12070219': "Client Engine disabled",
            '12071046': "Proactive Threat Scanning is not supported on this platform",
            '12071047': "Proactive Threat Scanning load error",
            '12071048': "SONAR content load error",
            '12071049': "Allow application",
            # Server events Possible values are:
            '12070301': "Server connected",
            '12070302': "No server response",
            '12070303': "Server connection failed",
            '12070304': "Server disconnected",
            '120B0001': "Cannot reach server",
            '120B0002': "Reconnected to the server",
            '120b0003': "Automatic upgrade complete",
            # Policy events Possible values are:
            '12070306': "New policy received",
            '12070307': "New policy applied",
            '12070308': "New policy failed",
            '12070309': "Cannot download policy",
            '120B0005': "Cannot download policy",
            '1207030A': "Have latest policy",
            '120B0004': "Have latest policy",
            # Antivirus engine events Possible values are:
            '12071006': "Scan omission",
            '12071007': "Definition file loaded",
            '1207100B': "Virus behavior detected",
            '1207100C': "Configuration changed",
            '12071010': "Definition file download",
            '12071012': "Sent to quarantine server",
            '12071013': "Delivered to Symantec",
            '12071014': "Security Response backup",
            '12071015': "Scan aborted",
            '12071016': "Symantec Endpoint Protection Auto-Protect Load error",
            '12071017': "Symantec Endpoint Protection Auto-Protect enabled",
            '12071018': "Symantec Endpoint Protection Auto-Protect disabled",
            '1207101A': "Scan delayed",
            '1207101B': "Scan restarted",
            '12071027': "Symantec Endpoint Protection is using old virus definitions",
            '12071041': "Scan suspended",
            '12071042': "Scan resumed",
            '12071043': "Scan duration too short",
            '12071045': "Scan enhancements failed",
            # Licensing events Possible values are:
            '1207101E': "License warning",
            '1207101F': "License error",
            '12071020': "License in grace period",
            '12071023': "License installed",
            '12071025': "License up-to-date",
            # Security events Possible values are:
            '1207102B': "Computer not compliant with security policy",
            '1207102C': "Computer compliant with security policy",
            '1207102D': "Tamper attempt",
            '12071034': "Login failed",
            '12071035': "Login succeeded",
            # Submission events Possible values are:
            '12120001': "System message from centralized reputation",
            '12120002': "Authentication token failure",
            '12120003': "Reputation failure",
            '12120004': "Reputation network failure",
            '12130001': "System message from Submissions",
            '12130002': "Submissions failure",
            '12130003': "Intrusion prevention submission",
            '12130004': "Antivirus detection submission",
            '12130005': "Antivirus advanced heuristic detection submission",
            '12130006': "Manual user submission",
            '12130007': "SONAR heuristic submission",
            '12130008': "SONAR detection submission",
            '12130009': "File Reputation submission",
            '1213000A': "Client authentication token request",
            '1213000B': "LiveUpdate error submission",
            '1213000C': "Process data submission",
            '1213000D': "Configuration data submission",
            '1213000E': "Network data submission",
            # Other events Possible values are:
            '1207020A': "Email post OK",
            '1207020B': "Email post failure",
            '1207020C': "Update complete",
            '1207020D': "Update failure",
            '1207020E': "Manual location change",
            '1207020F': "Location changed",
            '12070212': "Old rasdll version detected",
            '12070213': "Auto-update postponed",
            '12070305': "Mode changed",
            '1207030B': "Cannot apply HI script",
            '1207030C': "Content Update Server",
            '1207030D': "Content Update Packet",
            '12070500': "System message from device control",
            '12070600': "System message from anti-buffer overflow driver",
            '12070700': "System message from network access component",
            '12070800': "System message from LiveUpdate",
            '12070900': "System message from GUP",
            '12072000': "System message from Memory Exploit Mitigation",
            '12072007': "SymELAM disabled",  # not documented
            '12072008': "SymELAM enabled",  # not documented
            '12072009': "Intensive Protection disabled",
            '1207200A': "Intensive Protection enabled",
            '12071021': "Access denied warning",
            '12071022': "Log forwarding error",
            '12071044': "Client moved",
            '12071036': "Access denied warning",
            '12071000': "Message from Intrusion Prevention",
            '12071050': "SONAR disabled",
            '12071051': "SONAR enabled"
           }

'''seclog.log'''
seclog_event_id = {
            # Compliance events:
            209: "Host Integrity failed (TSLOG_SEC_NO_AV)",
            210: "Host Integrity passed (TSLOG_SEC_AV)",
            221: "Host Integrity failed but it was reported as PASS",
            237: "Host Integrity custom log entry",
            # Firewall and IPS events:
            201: "Invalid traffic by rule",  # SEP14.2.1
            202: "Port Scan",  # SEP14.2.1
            203: "Denial-of-service attack",  # SEP14.2.1
            204: "Trojan horse",  # SEP14.2.1
            205: "Executable file changed",  # SEP14.2.1
            206: "Intrusion Prevention System (Intrusion Detected,TSLOG_SEC_INTRUSION_DETECTED)",  # SEP14.2.1
            207: "Active Response",
            208: "MAC Spoofing",  # SEP14.2.1
            211: "Active Response Disengaged",
            216: "Executable file change detected",
            217: "Executable file change accepted",
            218: "Executable file change denied",
            219: "Active Response Canceled",  # SEP14.2.1
            220: "Application Hijacking",
            249: "Browser Protection event",
            # Application and Device control:
            238: "Device control disabled device",
            239: "Buffer Overflow Event",
            240: "Software protection has thrown an exception",
            241: "Not used",   # SEP14.2.1
            242: "Device control enabled the device",  # SEP14.2.1
            # Memory Exploit Mitigation events:
            250: "Memory Exploit Mitigation blocked an event",  # SEP14.2.1
            251: "Memory Exploit Mitigation allowed an event"  # SEP14.2.1
           }

seclog_severity = {
            range(0, 4): "Critical",
            range(4, 8): "Major",
            range(8, 12): "Minor",
            range(12, 16): "Information"
           }

seclog_protocol = {
            1: "OTHERS",
            2: "TCP",
            3: "UDP",
            4: "ICMP"
           }

seclog_direction = {
             0: "Unknown",
             1: "Incoming",
             2: "Outgoing"
            }

url_categories = {
                 1: "Adult/Mature Content",
                 3: "Pornography",
                 4: "Sex Education",
                 5: "Intimate Apparel/Swimsuit",
                 6: "Nudity",
                 7: "Gore/Extreme",
                 9: "Scam/Questionable Legality",
                 11: "Gambling",
                 14: "Violence/Intolerance",
                 15: "Weapons",
                 16: "Abortion",
                 17: "Hacking",
                 18: "Phishing",
                 20: "Entertainment",
                 21: "Business/Economy",
                 22: "Alternative Spirituality/Belief",
                 23: "Alcohol",
                 24: "Tobacco",
                 25: "Controlled Substances",
                 26: "Child Pornography",
                 27: "Education",
                 29: "Charitable/Non-Profit",
                 30: "Art/Culture",
                 31: "Finance",
                 32: "Brokerage/Trading",
                 33: "Games",
                 34: "Government/Legal",
                 35: "Military",
                 36: "Political/Social Advocacy",
                 37: "Health",
                 38: "Technology/Internet",
                 40: "Search Engines/Portals",
                 43: "Malicious Sources/Malnets",
                 44: "Malicious Outbound Data/Botnets",
                 45: "Job Search/Careers",
                 46: "News",
                 47: "Personals/Dating",
                 49: "Reference",
                 50: "Mixed Content/Potentially Adult",
                 51: "Chat (IM)/SMS",
                 52: "Email",
                 53: "Newsgroups/Forums",
                 54: "Religion",
                 55: "Social Networking",
                 56: "File Storage/Sharing",
                 57: "Remote Access",
                 58: "Shopping",
                 59: "Auctions",
                 60: "Real Estate",
                 61: "Society/Daily Living",
                 63: "Personal Sites",
                 64: "Restaurants/Food",
                 65: "Sports/Recreation",
                 66: "Travel",
                 67: "Vehicles",
                 68: "Humor/Jokes",
                 71: "Software Downloads",
                 83: "Peer-to-Peer (P2P)",
                 84: "Audio/Video Clips",
                 85: "Office/Business Applications",
                 86: "Proxy Avoidance",
                 87: "For Kids",
                 88: "Web Ads/Analytics",
                 89: "Web Hosting",
                 90: "Uncategorized",
                 92: "Suspicious",
                 93: "Sexual Expression",
                 95: "Translation",
                 96: "Web Infrastructure",
                 97: "Content Delivery Networks",
                 98: "Placeholders",
                 101: "Spam",
                 102: "Potentially Unwanted Software",
                 103: "Dynamic DNS Host",
                 104: "URL Shorteners",
                 105: "Email Marketing",
                 106: "E-Card/Invitations",
                 107: "Informational",
                 108: "Computer/Information Security",
                 109: "Internet Connected Devices",
                 110: "Internet Telephony",
                 111: "Online Meetings",
                 112: "Media Sharing",
                 113: "Radio/Audio Streams",
                 114: "TV/Video Streams",
                 116: "Cloud Infrastructure",
                 117: "Cryptocurrency",
                 118: "Piracy/Copyright Concerns",
                 121: "Marijuana",
                 124: "Compromised Sites"
                }

'''tralog.log'''
tralog_protocol = {
                   301: "TCP initiated",
                   302: "UDP datagram",
                   303: "Ping request",
                   304: "TCP completed",
                   305: "Traffic (other)",
                   306: "ICMPv4 packet",
                   307: "Ethernet packet",
                   308: "IP packet",
                   309: "ICMPv6 packet"
                  }

# https://www.iana.org/assignments/icmp-parameters/icmp-parameters.xhtml
icmp_type_code = {
                  0: {
                      'type': "Echo Reply",
                      0: "No Code"
                     },
                  1: {
                      'type': "Unassigned"
                     },
                  2: {
                      'type': "Unassigned"
                     },
                  3: {
                      'type': "Destination Unreachable",
                      0: "Net Unreachable",
                      1: "Host Unreachable",
                      2: "Protocol Unreachable",
                      3: "Port Unreachable",
                      4: "Fragmentation Needed and Do not Fragment was Set",
                      5: "Source Route Failed",
                      6: "Destination Network Unknown",
                      7: "Destination Host Unknown",
                      8: "Source Host Isolated",
                      9: "Communication with Destination Network is Administratively Prohibited",
                      10: "Communication with Destination Host is Administratively Prohibited",
                      11: "Destination Network Unreachable for Type of Service",
                      12: "Destination Host Unreachable for Type of Service",
                      13: "Communication Administratively Prohibited",
                      14: "Host Precedence Violation",
                      15: "Precedence cutoff in effect"
                     },
                  4: {
                      'type': "Source Quench (Deprecated)",
                      0: "No Code"
                     },
                  5: {
                      'type': "Redirect",
                      0: "Redirect Datagram for the Network (or subnet)",
                      1: "Redirect Datagram for the Host",
                      2: "Redirect Datagram for the Type of Service and Network",
                      3: "Redirect Datagram for the Type of Service and Host"
                     },
                  6: {
                      'type': "Alternate Host Address (Deprecated)",
                      0: "Alternate Address for Host"
                     },
                  7: {
                      'type': "Unassigned"
                     },
                  8: {
                      'type': "Echo",
                      0: "No Code"
                     },
                  9: {
                      'type': "Router Advertisement",
                      0: "Normal router advertisement",
                      16: "Does not route common traffic"
                     },
                  10: {
                       'type': "Router Solicitation",
                       0: "No Code"
                      },
                  11: {
                       'type': "Time Exceeded",
                       0: "Time to Live exceeded in Transit",
                       1: "Fragment Reassembly Time Exceeded"
                      },
                  12: {
                       'type': "Parameter Problem",
                       0: "Pointer indicates the error",
                       1: "Missing a Required Option",
                       2: "Bad Length"
                      },
                  13: {
                       'type': "Timestamp",
                       0: "No Code"
                      },
                  14: {
                       'type': "Timestamp Reply",
                       0: "No Code"
                      },
                  15: {
                       'type': "Information Request (Deprecated)",
                       0: "No Code"
                      },
                  16: {
                       'type': "Information Reply (Deprecated)",
                       0: "No Code"
                      },
                  17: {
                       'type': "Address Mask Request (Deprecated)",
                       0: "No Code"
                      },
                  18: {
                       'type': "Address Mask Reply (Deprecated)",
                       0: "No Code"
                      },
                  19: {
                       'type': "Reserved (for Security)"
                      },
                  range(20, 30): {
                                  'type': "Reserved (for Robustness Experiment)"
                                 },
                  30: {
                       'type': "Traceroute (Deprecated)"
                      },
                  31: {
                       'type': "Datagram Conversion Error (Deprecated)"
                      },
                  32: {
                       'type': "Mobile Host Redirect (Deprecated)"
                      },
                  33: {
                       'type': "IPv6 Where-Are-You (Deprecated)"
                      },
                  34: {
                       'type': "IPv6 I-Am-Here (Deprecated)"
                      },
                  35: {
                       'type': "Mobile Registration Request (Deprecated)"
                      },
                  36: {
                       'type': "Mobile Registration Reply (Deprecated)"
                      },
                  37: {
                       'type': "Domain Name Request (Deprecated)"
                      },
                  38: {
                       'type': "Domain Name Reply (Deprecated))"
                      },
                  39: {
                       'type': "SKIP (Deprecated)"
                      },
                  40: {
                       'type': "Photuris",
                       0: "Bad SPI",
                       1: "Authentication Failed",
                       2: "Decompression Failed",
                       3: "Decryption Failed",
                       4: "Need Authentication",
                       5: "Need Authorization"
                      },
                  41: {
                       'type': "ICMP messages utilized by experimental mobility protocols such as Seamoby"
                      },
                  42: {
                       'type': "Extended Echo Request",
                       0: "No Error",
                       range(1, 256): "Unassigned"
                      },
                  43: {
                       'type': "Extended Echo Reply",
                       0: "No Error",
                       1: "Malformed Query",
                       2: "No Such Interface",
                       3: "No Such Table Entry",
                       4: "Multiple Interfaces Satisfy Query",
                       range(5, 256): "Unassigned"
                      },
                  range(44, 253): {
                                   'type': "Unassigned"
                                  },
                  253: {
                        'type': "RFC3692-style Experiment 1"
                       },
                  254: {
                        'type': "RFC3692-style Experiment 2"
                       },
                  255: {
                        'type': "Reserved"
                       }
                 }

# https://www.iana.org/assignments/ieee-802-numbers/ieee-802-numbers.xhtml
eth_type = {
            range(257, 512): "Experimental",
            512: "XEROX PUP (see 0A00)",
            513: "PUP Addr Trans (see 0A01)",
            1024: "Nixdorf",
            1536: "XEROX NS IDP",
            1632: "DLOG",
            1633: "DLOG",
            2048: "Internet Protocol version 4 (IPv4)",
            2049: "X.75 Internet",
            2050: "NBS Internet",
            2051: "ECMA Internet",
            2052: "Chaosnet",
            2053: "X.25 Level 3",
            2054: "Address Resolution Protocol (ARP)",
            2055: "XNS Compatability",
            2056: "Frame Relay ARP",
            2076: "Symbolics Private",
            range(2184, 2187): "Xyplex",
            2304: "Ungermann-Bass net debugr",
            2560: "Xerox IEEE802.3 PUP",
            2561: "PUP Addr Trans",
            2989: "Banyan VINES",
            2990: "VINES Loopback",
            2991: "VINES Echo",
            4096: "Berkeley Trailer nego",
            range(4097, 4112): "Berkeley Trailer encap/IP",
            5632: "Valid Systems",
            8947: "TRILL",
            8948: "L2-IS-IS",
            16962: "PCS Basic Block Protocol",
            21000: "BBN Simnet",
            24576: "DEC Unassigned (Exp.)",
            24577: "DEC MOP Dump/Load",
            24578: "DEC MOP Remote Console",
            24579: "DEC DECNET Phase IV Route",
            24580: "DEC LAT",
            24581: "DEC Diagnostic Protocol",
            24582: "DEC Customer Protocol",
            24583: "DEC LAVC; SCA",
            range(24584, 24586): "DEC Unassigned",
            range(24592, 24597): "3Com Corporation",
            25944: "Trans Ether Bridging",
            25945: "Raw Frame Relay",
            28672: "Ungermann-Bass download",
            28674: "Ungermann-Bass dia/loop",
            range(28704, 28714): "LRT",
            28720: "Proteon",
            28724: "Cabletron",
            32771: "Cronus VLN",
            32772: "Cronus Direct",
            32773: "HP Probe",
            32774: "Nestar",
            32776: "AT&T",
            32784: "Excelan",
            32787: "SGI diagnostics",
            32788: "SGI network games",
            32789: "SGI reserved",
            32790: "SGI bounce server",
            32793: "Apollo Domain",
            32814: "Tymshare",
            32815: "Tigan; Inc.",
            32821: "Reverse Address Resolution Protocol (RARP)",
            32822: "Aeonic Systems",
            32824: "DEC LANBridge",
            range(32825, 32829): "DEC Unassigned",
            32829: "DEC Ethernet Encryption",
            32830: "DEC Unassigned",
            32831: "DEC LAN Traffic Monitor",
            range(32832, 32835): "DEC Unassigned",
            32836: "Planning Research Corp.",
            32838: "AT&T",
            32839: "AT&T",
            32841: "ExperData",
            32859: "Stanford V Kernel exp.",
            32860: "Stanford V Kernel prod.",
            32861: "Evans & Sutherland",
            32864: "Little Machines",
            32866: "Counterpoint Computers",
            32869: "Univ. of Mass. @ Amherst",
            32870: "Univ. of Mass. @ Amherst",
            32871: "Veeco Integrated Auto.",
            32872: "General Dynamics",
            32873: "AT&T",
            32874: "Autophon",
            32876: "ComDesign",
            32877: "Computgraphic Corp.",
            range(32878, 32888): "Landmark Graphics Corp.",
            32890: "Matra",
            32891: "Dansk Data Elektronik",
            32892: "Merit Internodal",
            range(32893, 32896): "Vitalink Communications",
            32896: "Vitalink TransLAN III",
            range(32897, 32900): "Counterpoint Computers",
            32923: "Appletalk",
            range(32924, 32927): "Datability",
            32927: "Spider Systems Ltd.",
            32931: "Nixdorf Computers",
            range(32932, 32948): "Siemens Gammasonics Inc.",
            range(32960, 32964): "DCA Data Exchange Cluster",
            32964: "Banyan Systems",
            32965: "Banyan Systems",
            32966: "Pacer Software",
            32967: "Applitek Corporation",
            range(32968, 32973): "Intergraph Corporation",
            range(32973, 32975): "Harris Corporation",
            range(32975, 32979): "Taylor Instrument",
            range(32979, 32981): "Rosemount Corporation",
            32981: "IBM SNA Service on Ether",
            32989: "Varian Associates",
            range(32990, 32992): "Integrated Solutions TRFS",
            range(32992, 32996): "Allen-Bradley",
            range(32996, 33009): "Datability",
            33010: "Retix",
            33011: "AppleTalk AARP (Kinetics)",
            range(33012, 33014): "Kinetics",
            33015: "Apollo Computer",
            33023: "Wellfleet Communications",
            33024: "Customer VLAN Tag Type (C-Tag; formerly called the Q-Tag) (initially Wellfleet)",
            range(33025, 33028): "Wellfleet Communications",
            range(33031, 33034): "Symbolics Private",
            33072: "Hayes Microcomputers",
            33073: "VG Laboratory Systems",
            range(33074, 33079): "Bridge Communications",
            range(33079, 33081): "Novell; Inc.",
            range(33081, 33086): "KTI",
            33096: "Logicraft",
            33097: "Network Computing Devices",
            33098: "Alpha Micro",
            33100: "SNMP",
            33101: "BIIN",
            33102: "BIIN",
            33103: "Technically Elite Concept",
            33104: "Rational Corp",
            range(33105, 33108): "Qualcomm",
            range(33116, 33119): "Computer Protocol Pty Ltd",
            range(33124, 33127): "Charles River Data System",
            33149: "XTP",
            33150: "SGI/Time Warner prop.",
            33152: "HIPPI-FP encapsulation",
            33153: "STP; HIPPI-ST",
            33154: "Reserved for HIPPI-6400",
            33155: "Reserved for HIPPI-6400",
            range(33156, 33165): "Silicon Graphics prop.",
            33165: "Motorola Computer",
            range(33178, 33188): "Qualcomm",
            33188: "ARAI Bunkichi",
            range(33189, 33199): "RAD Network Devices",
            range(33207, 33210): "Xyplex",
            range(33228, 33238): "Apricot Computers",
            range(33238, 33246): "Artisoft",
            range(33254, 33264): "Polygon",
            range(33264, 33267): "Comsat Labs",
            range(33267, 33270): "SAIC",
            range(33270, 33273): "VG Analytical",
            range(33283, 33286): "Quantum Software",
            range(33313, 33315): "Ascom Banking Systems",
            range(33342, 33345): "Advanced Encryption Syste",
            range(33407, 33411): "Athena Programming",
            range(33379, 33387): "Charles River Data System",
            range(33434, 33436): "Inst Ind Info Tech",
            range(33436, 33452): "Taurus Controls",
            range(33452, 34452): "Walker Richer & Quinn",
            range(34452, 34462): "Idea Courier",
            range(34462, 34466): "Computer Network Tech",
            range(34467, 34477): "Gateway Communications",
            34523: "SECTRA",
            34526: "Delta Controls",
            34525: "Internet Protocol version 6 (IPv6)",
            34527: "ATOMIC",
            range(34528, 34544): "Landis & Gyr Powers",
            range(34560, 34577): "Motorola",
            34667: "TCP/IP Compression",
            34668: "IP Autonomous Systems",
            34669: "Secure Data",
            34824: "IEEE Std 802.3 - Ethernet Passive Optical Network (EPON)",
            34827: "Point-to-Point Protocol (PPP)",
            34828: "General Switch Management Protocol (GSMP)",
            34887: "MPLS",
            34888: "MPLS with upstream-assigned label",
            34913: "Multicast Channel Allocation Protocol (MCAP)",
            34915: "PPP over Ethernet (PPPoE) Discovery Stage",
            34916: "PPP over Ethernet (PPPoE) Session Stage",
            34958: "IEEE Std 802.1X - Port-based network access control",
            34984: "IEEE Std 802.1Q - Service VLAN tag identifier (S-Tag)",
            range(35478, 35480): "Invisible Software",
            34997: "IEEE Std 802 - Local Experimental Ethertype",
            34998: "IEEE Std 802 - Local Experimental Ethertype",
            34999: "IEEE Std 802 - OUI Extended Ethertype",
            35015: "IEEE Std 802.11 - Pre-Authentication (802.11i)",
            35020: "IEEE Std 802.1AB - Link Layer Discovery Protocol (LLDP)",
            35045: "IEEE Std 802.1AE - Media Access Control Security",
            35047: "Provider Backbone Bridging Instance tag",
            35061: "IEEE Std 802.1Q  - Multiple VLAN Registration Protocol (MVRP)",
            35062: "IEEE Std 802.1Q - Multiple Multicast Registration Protocol (MMRP)",
            35085: "IEEE Std 802.11 - Fast Roaming Remote Request (802.11r)",
            35095: "IEEE Std 802.21 - Media Independent Handover Protocol",
            35113: "IEEE Std 802.1Qbe - Multiple I-SID Registration Protocol",
            35131: "TRILL Fine Grained Labeling (FGL)",
            35136: "IEEE Std 802.1Qbg - ECP Protocol (also used in 802.1BR)",
            35142: "TRILL RBridge Channel",
            35143: "GeoNetworking as defined in ETSI EN 302 636-4-1",
            35151: "NSH (Network Service Header)",
            36864: "Loopback",
            36865: "3Com(Bridge) XNS Sys Mgmt",
            36866: "3Com(Bridge) TCP-IP Sys",
            36867: "3Com(Bridge) loop detect",
            39458: "Multi-Topology",
            41197: "LoWPAN encapsulation",
            47082: "The Ethertype will be used to identify a Channel in which control messages are encapsulated as payload of GRE packets. When a GRE packet tagged with the Ethertype is received; the payload will be handed to the network processor for processing.",
            65280: "BBN VITAL-LanBridge cache",
            range(65280, 65296): "ISC Bunker Ramo",
            65535: "Reserved"
           }

tralog_direction = {
                    0: "Unknown",
                    1: "Incoming",
                    2: "Outgoing"
                   }

tralog_action = {
                 0: "Allow",
                 1: "Block",
                 2: "Ask",
                 3: "Continue",
                 4: "Terminate"
                }

tralog_severity = {
                   range(0, 4): "Critical",
                   range(4, 8): "Major",
                   range(8, 12): "Minor",
                   range(12, 16): "Information"
                  }

'''raw.log'''
raw_event_id = {
                401: "Raw Ethernet"
               }

raw_direction = {
                 0: "Unknown",
                 1: "Incoming",
                 2: "Outgoing"
                }

raw_action = {
              0: "Allow",
              1: "Block",
              2: "Ask",
              3: "Continue",
              4: "Terminate"
             }

'''processlog.log'''
processlog_action = {
                     0: "Allow",
                     1: "Block",
                     2: "Ask",
                     3: "Continue",
                     4: "Terminate"
                    }

test_mode = {
             0: "Production",
             1: "Yes"
            }

processlog_event_id = {
                       501: "Application Control Driver",
                       502: "Application Control Rules",
                       999: "Tamper Protection"
                      }

'''reports'''
idsxp_protocol = {
                  0: "HOPOPT",
                  1: "ICMP",
                  2: "IGMP",
                  3: "GGP",
                  4: "IPv4",
                  5: "ST",
                  6: "TCP",
                  7: "CBT",
                  8: "EGP",
                  9: "IGP",
                  10: "BBN-RCC-MON",
                  11: "NVP-II",
                  12: "PUP",
                  13: "ARGUS (deprecated)",
                  14: "EMCON",
                  15: "XNET",
                  16: "CHAOS",
                  17: "UDP",
                  18: "MUX",
                  19: "DCN-MEAS",
                  20: "HMP",
                  21: "PRM",
                  22: "XNS-IDP",
                  23: "TRUNK-1",
                  24: "TRUNK-2",
                  25: "LEAF-1",
                  26: "LEAF-2",
                  27: "RDP",
                  28: "IRTP",
                  29: "ISO-TP4",
                  30: "NETBLT",
                  31: "MFE-NSP",
                  32: "MERIT-INP",
                  33: "DCCP",
                  34: "3PC",
                  35: "IDPR",
                  36: "XTP",
                  37: "DDP",
                  38: "IDPR-CMTP",
                  39: "TP++",
                  40: "IL",
                  41: "IPv6",
                  42: "SDRP",
                  43: "IPv6-Route",
                  44: "IPv6-Frag",
                  45: "IDRP",
                  46: "RSVP",
                  47: "GRE",
                  48: "DSR",
                  49: "BNA",
                  50: "ESP",
                  51: "AH",
                  52: "I-NLSP",
                  53: "SWIPE (deprecated)",
                  54: "NARP",
                  55: "MOBILE",
                  56: "TLSP",
                  57: "SKIP",
                  58: "IPv6-ICMP",
                  59: "IPv6-NoNxt",
                  60: "IPv6-Opts",
                  61: "Any Host Internal Protocol",
                  62: "CFTP",
                  63: "Any Local Network",
                  64: "SAT-EXPAK",
                  65: "KRYPTOLAN",
                  66: "RVD",
                  67: "IPPC",
                  68: "Any Distributed File System",
                  69: "SAT-MON",
                  70: "VISA",
                  71: "IPCV",
                  72: "CPNX",
                  73: "CPHB",
                  74: "WSN",
                  75: "PVP",
                  76: "BR-SAT-MON",
                  77: "SUN-ND",
                  78: "WB-MON",
                  79: "WB-EXPAK",
                  80: "ISO-IP",
                  81: "VMTP",
                  82: "SECURE-VMTP",
                  83: "VINES",
                  84: "TTP/IPTM",
                  85: "NSFNET-IGP",
                  86: "DGP",
                  87: "TCF",
                  88: "EIGRP",
                  89: "OSPFIGP",
                  90: "Sprite-RPC",
                  91: "LARP",
                  92: "MTP",
                  93: "AX.25",
                  94: "IPIP",
                  95: "MICP (deprecated)",
                  96: "SCC-SP",
                  97: "ETHERIP",
                  98: "ENCAP",
                  99: "Any Private Encryption Scheme",
                  100: "GMTP",
                  101: "IFMP",
                  102: "PNNI",
                  103: "PIM",
                  104: "ARIS",
                  105: "SCPS",
                  106: "QNX",
                  107: "A/N",
                  108: "IPComp",
                  109: "SNP",
                  110: "Compaq-Peer",
                  111: "IPX-in-IP",
                  112: "VRRP",
                  113: "PGM",
                  114: "Any 0-hop Protocol",
                  115: "L2TP",
                  116: "DDX",
                  117: "IATP",
                  118: "STP",
                  119: "SRP",
                  120: "UTI",
                  121: "SMP",
                  122: "SM (deprecated)",
                  123: "PTP",
                  124: "ISIS over IPv4",
                  125: "FIRE",
                  126: "CRTP",
                  127: "CRUDP",
                  128: "SSCOPMCE",
                  129: "IPLT",
                  130: "SPS",
                  131: "PIPE",
                  132: "SCTP",
                  133: "FC",
                  134: "RSVP-E2E-IGNORE",
                  135: "Mobility Header",
                  136: "UDPLite",
                  137: "MPLS-in-IP",
                  138: "manet",
                  139: "HIP",
                  140: "Shim6",
                  141: "WESP",
                  142: "ROHC",
                  143: "Ethernet",
                  range(144, 252): "Unassigned",
                  253: "Experementation/Testing",
                  254: "Experementation/Testing",
                  255: "Reserved"
                }
