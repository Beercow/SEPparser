# Log Line Information
Information was derived from https://support.symantec.com/en_US/article.TECH100099.html

#### Version 1 has the following fields:

Time,Event,Category,Logger,Computer,User,Virus,File,Wanted Action 1,Wanted Action 2,Real Action,Virus Type,Flags,Description,ScanID,New_Ext,Group ID,Event Data,VBin_ID,Virus ID,Quarantine Forward Status,Access,SND_Status,Compressed,Depth,Still Infected,Def Info,Def Sequence Number,Clean Info,Delete Info,Backup ID,Parent,GUID,Client Group,Address,Domain Name,NT Domain,MAC Address,Version,Remote Machine,Remote Machine IP,Action 1 Status,Action 2 Status,License Feature Name,License Feature Version,License Serial Number,License Fulfillment ID,License Start Date,License Expiration Date,License LifeCycle,License Seats Total,License Seats,Error Code,License Seats Delta,Status,Domain GUID,Log Session GUID,VBin Session ID,Login Domain,Event Data 2

#### Version 2 has the same fields as version 1 plus some extras:

Time,Event,Category,Logger,Computer,User,Virus,File,Wanted Action 1,Wanted Action 2,Real Action,Virus Type,Flags,Description,ScanID,New_Ext,Group ID,Event Data,VBin_ID,Virus ID,Quarantine Forward Status,Access,SND_Status,Compressed,Depth,Still Infected,Def Info,Def Sequence Number,Clean Info,Delete Info,Backup ID,Parent,GUID,Client Group,Address,Domain Name,NT Domain,MAC Address,Version,Remote Machine,Remote Machine IP,Action 1 Status,Action 2 Status,License Feature Name,License Feature Version,License Serial Number,License Fulfillment ID,License Start Date,License Expiration Date,License LifeCycle,License Seats Total,License Seats,Error Code,License Seats Delta,Status,Domain GUID,Log Session GUID,VBin Session ID,Login Domain,Event Data 2,Eraser Category ID,Dynamic Categoryset ID,Dynamic Subcategoryset ID,Display Name To Use,Reputation Disposition,Reputation Confidence,First Seen,Reputation Prevalence,Downloaded URL,Creator For Dropper,CIDS State,Behavior Risk Level,Detection Type,Acknowledge Text,VSIC State,Scan GUID,Scan Duration,Scan Start Time,TargetApp Type,Scan Command GUID

## Entries

| Field                                              | Description                                                                                                                          |
| -------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------ |
| Time                                               | Time of event.                                                                                                                       |
| Event                                              | 1 IS_ALERT<br>2 SCAN_STOP<br>3 SCAN_START<br>4 PATTERN_UPDATE<br>5 INFECTION<br>6 FILE_NOT_OPEN<br>7 LOAD_PATTERN<br>8 MESSAGE_INFO<br>9 MESSAGE_ERROR<br>10 CHECKSUM<br>11 TRAP<br>12 CONFIG_CHANGE<br>13 SHUTDOWN<br>14 STARTUP<br>16 PATTERN_DOWNLOAD<br>17 TOO_MANY_VIRUSES<br>18 FWD_TO_QSERVER<br>19 SCANDLVR<br>20 BACKUP<br>21 SCAN_ABORT<br>22 RTS_LOAD_ERROR<br>23 RTS_LOAD<br>24 RTS_UNLOAD<br>25 REMOVE_CLIENT<br>26 SCAN_DELAYED<br>27 SCAN_RESTART<br>28 ADD_SAVROAMCLIENT_TOSERVER<br>29 REMOVE_SAVROAMCLIENT_FROMSERVER<br>30 LICENSE_WARNING<br>31 LICENSE_ERROR<br>32 LICENSE_GRACE<br>33 UNAUTHORIZED_COMM<br>34 LOG_FWD_THRD_ERR<br>35 LICENSE_INSTALLED<br>36 LICENSE_ALLOCATED<br>37 LICENSE_OK<br>38 LICENSE_DEALLOCATED<br>39 BAD_DEFS_ROLLBACK<br>40 BAD_DEFS_UNPROTECTED<br>41 SAV_PROVIDER_PARSING_ERROR<br>42 RTS_ERROR<br>43 COMPLIANCE_FAIL<br>44 COMPLIANCE_SUCCESS<br>45 SECURITY_SYMPROTECT_POLICYVIOLATION<br>46 ANOMALY_START<br>47 DETECTION_ACTION_TAKEN<br>48 REMEDIATION_ACTION_PENDING<br>49 REMEDIATION_ACTION_FAILED<br>50 REMEDIATION_ACTION_SUCCESSFUL<br>51 ANOMALY_FINISH<br>52 COMMS_LOGIN_FAILED<br>53 COMMS_LOGIN_SUCCESS<br>54 COMMS_UNAUTHORIZED_COMM<br>55 CLIENT_INSTALL_AV<br>56 CLIENT_INSTALL_FW<br>57 CLIENT_UNINSTALL<br>58 CLIENT_UNINSTALL_ROLLBACK<br>59 COMMS_SERVER_GROUP_ROOT_CERT_ISSUE<br>60 COMMS_SERVER_CERT_ISSUE<br>61 COMMS_TRUSTED_ROOT_CHANGE<br>62 COMMS_SERVER_CERT_STARTUP_FAILED<br>63 CLIENT_CHECKIN<br>64 CLIENT_NO_CHECKIN<br>65 SCAN_SUSPENDED<br>66 SCAN_RESUMED<br>67 SCAN_DURATION_INSUFFICIENT<br>68 CLIENT_MOVE<br>69 SCAN_FAILED_ENHANCED<br>70 COMPLIANCE_FAILEDAUDIT<br>71 HEUR_THREAT_NOW_WHITELISTED<br>72 INTERESTING_PROCESS_DETECTED_START<br>73 LOAD_ERROR_BASH<br>74 LOAD_ERROR_BASH_DEFINITIONS<br>75 INTERESTING_PROCESS_DETECTED_FINISH<br>76 BASH_NOT_SUPPORTED_FOR_OS<br>77 HEUR_THREAT_NOW_KNOWN<br>78 DISABLE_BASH<br>79 ENABLE_BASH<br>80 DEFS_LOAD_FAILED<br>81 LOCALREP_CACHE_SERVER_ERROR<br>82 REPUTATION_CHECK_TIMEOUT<br>83 SYMEPSECFILTER_DRIVER_ERROR<br>84 VSIC_COMMUNICATION_WARNING<br>85 VSIC_COMMUNICATION_RESTORED<br>86 ELAM_LOAD_FAILED<br>87 ELAM_INVALID_OS<br>88 ELAM_ENABLE<br>89 ELAM_DISABLE<br>90 ELAM_BAD<br>91 ELAM_BAD_REPORTED_AS_UNKNOWN<br>92 DISABLE_SYMPROTECT<br>93 ENABLE_SYMPROTECT<br>94 NETSEC_EOC_PARSE_FAILED |
| Category                                           | 1 Infection<br>2 Summary<br>3 Pattern<br>4 Security                                                                                  |
| Logger                                             | 0  Scheduled<br>1  Manual<br>2  Real_Time<br>3  Integrity_Shield<br>6  Console<br>7  VPDOWN<br>8  System<br>9  Startup<br>10 Idle<br>11 DefWatch<br>12 Licensing<br>13 Manual_Quarantine<br>14 SymProtect<br>15 Reboot_Processing<br>16 Bash<br>17 SymElam<br>18 PowerEraser<br>19 EOCScan<br>100 LOCAL_END<br>101 Client<br>102 Forwarded<br>256 Transport_Client |
| Computer                                           | Computer name.                                                                                                                       |
| User                                               | User name.                                                                                                                           |
| Virus                                              | Virus Name (Virus Found event only)                                                                                                  |
| File                                               | Virus's Location (Virus Found event only)                                                                                            |
| Wanted Action 1                                    | Primary Action (Virus Found event only)<br><br>4294967295# Invalid<br>1 Quarantine<br>2 Rename<br>3 Delete<br>4 Leave Alone<br>5 Clean<br>6 Remove Macros<br>7 Save file as...<br>8 Sent to backend<br>9 Restore from Quarantine<br>10 Rename Back (unused)<br>11 Undo Action<br>12 Error<br>13 Backup to quarantine (backup view)<br>14 Pending Analysis<br>15 Partially Fixed<br>16 Terminate Process Required<br>17 Exclude from Scanning<br>18 Reboot Processing<br>19 Clean by Deletion<br>20 Access Denied<br>21 TERMINATE PROCESS ONLY<br>22 NO REPAIR<br>23 FAIL<br>24 RUN POWERTOOL<br>25 NO REPAIR POWERTOOL<br>110 INTERESTING PROCESS CAL<br>111 INTERESTING PROCESS DETECTED<br>1000 INTERESTING PROCESS HASHED DETECTED<br>1001 DNS HOST FILE EXCEPTION |
| Wanted Action 2                                    | Secondary Action  (Virus Found event only)<br><br>4294967295# Invalid<br>1 Quarantine<br>2 Rename<br>3 Delete<br>4 Leave Alone<br>5 Clean<br>6 Remove Macros<br>7 Save file as...<br>8 Sent to backend<br>9 Restore from Quarantine<br>10 Rename Back (unused)<br>11 Undo Action<br>12 Error<br>13 Backup to quarantine (backup view)<br>14 Pending Analysis<br>15 Partially Fixed<br>16 Terminate Process Required<br>17 Exclude from Scanning<br>18 Reboot Processing<br>19 Clean by Deletion<br>20 Access Denied<br>21 TERMINATE PROCESS ONLY<br>22 NO REPAIR<br>23 FAIL<br>24 RUN POWERTOOL<br>25 NO REPAIR POWERTOOL<br>110 INTERESTING PROCESS CAL<br>111 INTERESTING PROCESS DETECTED<br>1000 INTERESTING PROCESS HASHED DETECTED<br>1001 DNS HOST FILE EXCEPTION |
| Real Action                                        | Action Taken (Virus Found event only)<br><br>4294967295# Invalid<br>1 Quarantine<br>2 Rename<br>3 Delete<br>4 Leave Alone<br>5 Clean<br>6 Remove Macros<br>7 Save file as...<br>8 Sent to backend<br>9 Restore from Quarantine<br>10 Rename Back (unused)<br>11 Undo Action<br>12 Error<br>13 Backup to quarantine (backup view)<br>14 Pending Analysis<br>15 Partially Fixed<br>16 Terminate Process Required<br>17 Exclude from Scanning<br>18 Reboot Processing<br>19 Clean by Deletion<br>20 Access Denied<br>21 TERMINATE PROCESS ONLY<br>22 NO REPAIR<br>23 FAIL<br>24 RUN POWERTOOL<br>25 NO REPAIR POWERTOOL<br>110 INTERESTING PROCESS CAL<br>111 INTERESTING PROCESS DETECTED<br>1000 INTERESTING PROCESS HASHED DETECTED<br>1001 DNS HOST FILE EXCEPTION |
| Virus Type                                         | 48 Heuristic<br>64 Reputation<br>80 Hack Tools<br>96 Spyware<br>112 Trackware<br>128 Dialers<br>144 Remote Access<br>160 Adware<br>176 Joke Programs<br>224 Heuristic Application |
| Flags                                              | Indicates what kind of action the Eventblock is.<br><br>&nbsp;&nbsp;&nbsp;&nbsp;if Flag & 0x400000:<br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Flag = Flag + "EB_ACCESS_DENIED "<br><br>&nbsp;&nbsp;&nbsp;&nbsp;if Flag & 0x800000:<br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Flag = Flag + "EB_NO_VDIALOG "<br><br>&nbsp;&nbsp;&nbsp;&nbsp;if Flag & 0x1000000:<br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Flag = Flag + "EB_LOG "<br><br>&nbsp;&nbsp;&nbsp;&nbsp;if Flag & 0x2000000:<br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Flag = Flag + "EB_REAL_CLIENT "<br><br>&nbsp;&nbsp;&nbsp;&nbsp;if Flag & 0x4000000:<br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Flag = Flag + "EB_ENDUSER_BLOCKED "<br><br>&nbsp;&nbsp;&nbsp;&nbsp;if Flag & 0x8000000:<br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Flag = Flag + "EB_AP_FILE_WIPED "<br><br>&nbsp;&nbsp;&nbsp;&nbsp;if Flag & 0x10000000:<br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Flag = Flag + "EB_PROCESS_KILLED "<br><br>&nbsp;&nbsp;&nbsp;&nbsp;if Flag & 0x20000000:<br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Flag = Flag + "EB_FROM_CLIENT "<br><br>&nbsp;&nbsp;&nbsp;&nbsp;if Flag & 0x40000000:<br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Flag = Flag + "EB_EXTRN_EVENT "<br><br>&nbsp;&nbsp;&nbsp;&nbsp;if Flag & 0x1FF:<br><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;if Flag & 0x1:<br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Flag = Flag + "FA_SCANNING_MEMORY "<br><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;if Flag & 0x2:<br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Flag = Flag + "FA_SCANNING_BOOT_SECTOR "<br><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;if Flag & 0x4:<br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Flag = Flag + "FA_SCANNING_FILE "<br><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;if Flag & 0x8:<br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Flag = Flag + "FA_SCANNING_BEHAVIOR "<br><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;if Flag & 0x10:<br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Flag = Flag + "FA_SCANNING_CHECKSUM "<br><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;if Flag & 0x20:<br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Flag = Flag + "FA_WALKSCAN "<br><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;if Flag & 0x40:<br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Flag = Flag + "FA_RTSSCAN "<br><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;if Flag & 0x80:<br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Flag = Flag + "FA_CHECK_SCAN "<br><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;if Flag & 0x100:<br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Flag = Flag + "FA_CLEAN_SCAN "<br><br>&nbsp;&nbsp;&nbsp;&nbsp;if Flag & 0x803FFE00:<br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Flag = Flag + "EB_N_OVERLAYS("<br><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;if Flag & 0x200:<br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Flag = Flag + "N_OFFLINE "<br><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;if Flag & 0x400:<br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Flag = Flag + "N_INFECTED "<br><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;if Flag & 0x800:<br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Flag = Flag + "N_REPSEED_SCAN "<br><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;if Flag & 0x1000:<br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Flag = Flag + "N_RTSNODE "<br><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;if Flag & 0x2000:<br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Flag = Flag + "N_MAILNODE "<br><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;if Flag & 0x4000:<br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Flag = Flag + "N_FILENODE "<br><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;if Flag & 0x8000:<br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Flag = Flag + "N_COMPRESSED "<br><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;if Flag & 0x10000:<br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Flag = Flag + "N_PASSTHROUGH "<br><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;if Flag & 0x40000:<br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Flag = Flag + "N_DIRNODE "<br><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;if Flag & 0x80000:<br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Flag = Flag + "N_ENDNODE "<br><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;if Flag & 0x100000:<br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Flag = Flag + "N_MEMNODE "<br><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;if Flag & 0x200000:<br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Flag = Flag + "N_ADMIN_REQUEST_REMEDIATION "<br><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Flag = Flag[:-1] + ")" |
| Description                                        | Message that will be found on the "Properties" page (Event Log events only) or message indicating Scan start or Scan stop along with results. (Scan History events only) |
| ScanID                                             | ID number of associated scan (for Scan History events and Virus Found events)                                                        |
| New_Ext                                            | Will require further investigation as to the purpose of this log entry.                                                              |
| Group ID                                           | Indicates the Group ID.                                                                                                              |
| Event Data                                         | Information varies per event (see below)                                                                                             |
| VBin_ID                                            | Stores the ID of the file in Quarantine if it is Quarantined.                                                                        |
| Virus ID                                           | ID of the particular virus.                                                                                                          |
| Quarantine Forward Status                          | Indicates the status of the Quarantine attempt.<br><br>0 NONE<br>1 FAILED<br>2 OK                                                    |
| Access                                             | This stores the "operation flags"<br><br>0x00000001 READ<br>0x00000002 WRITE<br>0x00000004 EXEC<br>0x00000008 IN_TABLE<br>0x00000010 REJECT_ACTION<br>0x00000020 ACTION_COMPLETE<br>0x00000040 DELETE_WHEN_COMPLETE<br>0x00000080 CLIENT_REQUEST<br>0x00000100 OWNED_BY_USER<br>0x00000200 DELETE<br>0x00000800 OWNED_BY_QUEUE<br>0x00001000 FILE_IN_CACHE<br>0x00002000 SCAN<br>0x00004000 GET_TRAP_DATA<br>0x00008000 USE_TRAP_DATA<br>0x00010000 FILE_NEEDS_SCAN<br>0x00020000 BEFORE_OPEN<br>0x00040000 AFTER_OPEN<br>0x00080000 SCAN_BOOT_SECTOR<br>0x10000000 COMING_FROM_NAVAP<br>0x20000000 BACKUP_TO_QUARANTINE |
| SND_Status                                         | Will require further investigation as to the purpose of this log entry.                                                              |
| Compressed                                         | Indicated whether it is or is in a compressed file or not.<br><br>0 No<br>1 Yes                                                      |
| Depth                                              | Indicated at what depth IN a compressed file the virus was found.                                                                    |
| Still Infected                                     | Tells whether file is still infected or not.<br><br>0 No<br>1 Yes                                                                    |
| Def Info                                           | Version of Virus Definitions Used (Virus Found event only)                                                                           |
| Def Sequence Number                                | The Definition Sequence Number of the Virus Definitions used.                                                                        |
| Clean Info                                         | Indicates whether file is cleanable or not.<br><br>0 CLEANABLE<br>1 NO CLEAN PATTERN<br>2 NOT CLEANABLE                              |
| Delete Info                                        | Indicates whether file is deletable or not.<br><br>0 Unknown<br>1 Unknonw<br>4 DELETABLE<br>5 NOT DELETABLE                          |
| Backup ID                                          | Stores the ID of the file stored in Backup if it is backed up.                                                                       |
| Parent                                             | Name of Parent if is a Managed Client                                                                                                |
| GUID                                               | GUID of the machine (Virus Found event only)                                                                                         |
| Client Group                                       | Stores the client group, if set.                                                                                                     |
| Address                                            | IP or IPX address in the form IP-xxx.xxx.xxx.xxx                                                                                     |
| Domain Name                                        | Server group. Set servers only.                                                                                                      |
| NT Domain                                          | Windows domain or workgroup                                                                                                          |
| MAC Address                                        | Hardware address                                                                                                                     |
| Version                                            | Software version                                                                                                                     |
| Remote Machine                                     | Will require further investigation as to the purpose of this log entry.                                                              |
| Remote Machine IP                                  | Will require further investigation as to the purpose of this log entry.                                                              |
| Action 1 Status                                    | Will require further investigation as to the purpose of this log entry.                                                              |
| Action 2 Status                                    | Will require further investigation as to the purpose of this log entry.                                                              |
| License Feature Name                               | The product name and license type.                                                                                                   |
| License Feature Version                            | The product code, indicating product type, version, and suffix. This information is read from the license file.                      |
| License Serial Number                              | The license serial number, which is read from the license file.                                                                      |
| License Fulfillment ID                             | The license fulfillment ID, which is read from the license file.                                                                     |
| License Start Date                                 | The license start date time, which is read from the license file.                                                                    |
| License Expiration Date                            | The end date of the license period.                                                                                                  |
| License LifeCycle                                  | Will require further investigation as to the purpose of this log entry.                                                              |
| License Seats Total                                | Will require further investigation as to the purpose of this log entry.                                                              |
| License Seats                                      | Will require further investigation as to the purpose of this log entry.                                                              |
| Error Code                                         | Will require further investigation as to the purpose of this log entry.                                                              |
| License Seats Delta                                | Will require further investigation as to the purpose of this log entry.                                                              |
| Eraser Status                                      | 0 Success<br>1 Reboot Required<br>2 Nothing To Do<br>3 Repaired<br>4 Deleted<br>5 False<br>6 Abort<br>7 Continue<br>8 Service Not Stopped<br>9 Application Heuristic Scan Failure<br>10 Cannot Remediate<br>11 Whitelist Failure<br>12 Driver Failure<br>13 Reserved01<br>13 Commercial Application List Failure<br>13 Application Heuristic Scan Invalid OS<br>13 Content Manager Data Error<br>999 Leave Alone<br>1000 Generic Failure<br>1001 Out Of Memory<br>1002 Not Initialized<br>1003 Invalid Argument<br>1004 Insufficient Buffer<br>1005 Decryption Error<br>1006 File Not Found<br>1007 Out Of Range<br>1008 COM Error<br>1009 Partial Failure<br>1010 Bad Definitions<br>1011 Invalid Command<br>1012 No Interface<br>1013 RSA Error<br>1014 Path Not Empty<br>1015 Invalid Path<br>1016 Path Not Empty<br>1017 File Still Present<br>1018 Invalid OS<br>1019 Not Implemented<br>1020 Access Denied<br>1021 Directory Still Present<br>1022 Inconsistent State<br>1023 Timeout<br>1024 Action Pending<br>1025 Volume Write Protected<br>1026 Not Reparse Point<br>1027 File Exists<br>1028 Target Protected<br>1029 Disk Full<br>1030 Shutdown In Progress<br>1031 Media Error<br>1032 Network Defs Error |
| Domain GUID                                        | Domain ID                                                                                                                            |
| Log Session GUID                                   | This is an ID used by the client to keep track of related threat events.                                                             |
| VBin Session ID                                    | Will require further investigation as to the purpose of this log entry.                                                              |
| Login Domain                                       | The Windows domain.                                                                                                                  |
| Event Data 2 &#42;                                 | Information varies per event (see below)                                                                                             |
| Eraser Category ID &#42;                           | 1 HeuristicTrojanWorm<br>2 HeuristicKeyLogger<br>100 CommercialRemoteControl<br>101 CommercialKeyLogger<br>200 Cookie<br>300 Shields |
| Dynamic Categoryset ID &#42;                       | 1 MALWARE<br>2 SECURITY_RISK<br>3 POTENTIALLY_UNWANTED_APPLICATIONS<br>4 EXPERIMENTAL_HEURISTIC<br>5 LEGACY_VIRAL<br>6 LEGACY_NON_VIRAL<br>7 CATEGORY_CRIMEWARE<br>8 ADVANCED_HEURISTICS<br>9 REPUTATION_BACKED_ADVANCED_HEURISTICS<br>10 PREVALENCE_BACKED_ADVANCED_HEURISTICS |
| Dynamic Subcategoryset ID &#42;                    | Will require further investigation as to the purpose of this log entry.                                                              |
| Display Name To Use &#42;                          | 0 Application Name<br>1 VID Virus Name                                                                                               |
| Reputation Disposition &#42;                       | 0 Good<br>1 Bad<br>127 Unknown                                                                                                       |
| Reputation Confidence &#42;                        | The Confidence level that produced the conviction.<br><br>>= 100: Extremely High [100..]<br>>= 65: High [65..99]<br>>= 25: Medium [25..64]<br>>= 10: Low [10..24]<br>>=1: Symantec knows very little about the file/unknown [1..9]<br>0 is not a valid value. We can say unknown also for 0.<br>Default is 0 |
| First Seen &#42;                                   | When the threat was first discovered by Symantec, as downloaded from Symantec's web site.                                            |
| Reputation Prevalence &#42;                        | The prevalence data for the application<br><br>0: Unknown.<br>1-50: Very low<br>51-100: Low<br>101-150: Moderate<br>151-200: High<br>201-255: Very high<br>> 255: Very high<br>Default is 0 |
| Downloaded URL &#42;                               | The source URL of the first drop on this computer.                                                                                   |
| Creator For Dropper &#42;                          | The creator process of the dropper threat.                                                                                           |
| CIDS State &#42;                                   | Network intrusion prevention status:<br><br>0 = Off<br>1 = On<br>2 = Not installed<br>3 = Off by administrator policy<br>127 = Unknown.<br>Default is 127. |
| Behavior Risk Level &#42;                          | The risk level (high, med, low) for the convicted threat.<br><br>0 -- Unknown<br>1 or 2 -- Low<br>3 -- Medium<br>4 -- High<br>Default is 0. |
| Detection Type &#42;                               | 0 Traditional<br>1 Heuristic                                                                                                         |    
| Acknowledge Text &#42;                             | Will require further investigation as to the purpose of this log entry.                                                              |
| VSIC State &#42;                                   | 0 Off<br>1 On<br>2 Failed                                                                                                            |
| Scan GUID &#42;                                    | Will require further investigation as to the purpose of this log entry.                                                              |
| Scan Duration &#42;                                | Length of the scan                                                                                                                   |
| Scan Start Time &#42;                              | The time that the scan started.                                                                                                      |
| TargetApp Type &#42;                               | 0 Normal<br>1 Modern (Metro)                                                                                                         |
| Scan Command GUID &#42;                            | Will require further investigation as to the purpose of this log entry.                                                              |
| Field 113 &dagger;                                 | Will require further investigation as to the purpose of this log entry.                                                              |
| Location &dagger;                                  | The location used when the event occured.                                                                                            |
| Field 115 &dagger;                                 | Will require further investigation as to the purpose of this log entry.                                                              |
| Digital Signatures Signer &dagger;                 | The subject of the certificate.                                                                                                      |
| Digital Signatures Issuer &dagger;                 | If an executable from a detection event is signed, this field indicates its certificate authority.                                   |
| Digital Signatures Certificate Thumbprint &dagger; | The unique ID (or thumbprint) of the digital certificate.                                                                            |
| Field 119 &dagger;                                 | Will require further investigation as to the purpose of this log entry.                                                              |
| Digital Signatures Serial Number &dagger;          | The identification (certificate serial number) of the certificate issued by the certificate authority for the executable.            |
| Digital Signatures Signing Time &dagger;           | Will require further investigation as to the purpose of this log entry.                                                              |
| Field 122 &dagger;                                 | Will require further investigation as to the purpose of this log entry.                                                              |
| Field 123 &dagger;                                 | Will require further investigation as to the purpose of this log entry.                                                              |
| Field 124 &dagger;                                 | Will require further investigation as to the purpose of this log entry.                                                              |
| Field 125 &dagger;                                 | Will require further investigation as to the purpose of this log entry.                                                              |
| Field 126 &dagger;                                 | Will require further investigation as to the purpose of this log entry.                                                              |

## Event Data

### 101

| Field                      | Description                                                              |
| -------------------------- | ------------------------------------------------------------------------ |
| Field 1                    | 101                                                                      |
| GUID                       | This is an ID used by the client to keep track of related threat events. |
| Field 3                    | Will require further investigation as to the purpose of this log entry.  |
| Num Side Effects Repaired  | Will require further investigation as to the purpose of this log entry.  |
| Anomaly Action Type        | Type of remediation. (Human readable form)                               |
| Anomaly Action Operation   | Remediation action. (Human readable form)                                |
| Field 7                    | Will require further investigation as to the purpose of this log entry.  |
| Anomaly Name               | Virus Name                                                               |
| Anomaly Categories         | Combination of Categoryset\Subcategoryset ID separated by semicolon      | 
| Anomaly Action Type ID     | Type of remediation.                                                     |
| Anomaly Action OperationID | Remediation action.                                                      |
| Previous Log GUID          | This is an ID used by the client to keep track of related threat events. |
| Field 13                   | Will require further investigation as to the purpose of this log entry.  |

### 201

| Field                      | Description                                                             |
| -------------------------- | ----------------------------------------------------------------------- |
| Field 1                    | 201                                                                     |
| Field 2                    | Will require further investigation as to the purpose of this log entry. |
| Field 3                    | Will require further investigation as to the purpose of this log entry. |
| Field 4                    | Will require further investigation as to the purpose of this log entry. |
| Field 5                    | Will require further investigation as to the purpose of this log entry. |
| Field 6                    | Will require further investigation as to the purpose of this log entry. |
| Field 7                    | Will require further investigation as to the purpose of this log entry. |
| Field 8                    | Will require further investigation as to the purpose of this log entry. |
| Field 9                    | Will require further investigation as to the purpose of this log entry. | 
| Field 10                   | Will require further investigation as to the purpose of this log entry. |
| Field 11                   | Will require further investigation as to the purpose of this log entry. |
| Field 12                   | Will require further investigation as to the purpose of this log entry. |
| Field 13                   | Will require further investigation as to the purpose of this log entry. |

### 301

| Field                      | Description                                                             |
| -------------------------- | ----------------------------------------------------------------------- |
| Field 1                    | 301                                                                     |
| Actor PID                  | Process ID for acting process                                           |
| Actor                      | Process performing the action                                           |
| Event                      | 1 File Create<br>2 File Delete<br>3 File Open<br>6 Directory Create<br>7 Directory Delete<br>14 Registry Key Create<br>15 Registry Key Delete<br>16 Registry Value Delete<br>17 Registry Value Set<br>18 Registry Key Rename<br>19 Registry Key Set Security<br>45 File Set Security<br>46 Directory Set Security<br>55 Process Open<br>56 Process Duplicate |
| Target PID                 | Process ID for target process                                           |
| Target                     | What is being targeted                                                  |
| Target Process             | The process that is being targeted                                      |
| Field 8                    | Will require further investigation as to the purpose of this log entry. |
| Field 9                    | Will require further investigation as to the purpose of this log entry. | 
| Field 10                   | Will require further investigation as to the purpose of this log entry. |
| Field 11                   | Will require further investigation as to the purpose of this log entry. |
| Field 12                   | Will require further investigation as to the purpose of this log entry. |
| Field 13                   | Will require further investigation as to the purpose of this log entry. |

### Scan Entries

<table>
    <thead>
        <tr>
            <th>Field</th>
            <th>Description</th>
            <th>Entry</th>
        </tr>
    </thead>
    <tbody>
        <tr>
            <td rowspan=5>Field 1</td>
            <td rowspan=5>description</td>
            <td>Scan Status</td>
        </tr>
        <tr>
            <td>Risks</td>
        </tr>
        <tr>
            <td>Scanned</td>
        </tr>
        <tr>
            <td>Files/Folders/Drives Omitted</td>
        </tr>
        <tr>
            <td>Trusted Files Skipped</td>
        </tr>
        <tr>
            <td>Field 2</td>
            <td>N/A</td>
            <td>N/A</td>
        </tr>
        <tr>
            <td>Field 3</td>
            <td>N/A</td>
            <td>N/A</td>
        </tr>
        <tr>
            <td>Field 4</td>
            <td>N/A</td>
            <td>N/A</td>
        </tr>
        <tr>
            <td>Field 5</td>
            <td>N/A</td>
            <td>N/A</td>
        </tr>
        <tr>
            <td>Field 6</td>
            <td>N/A</td>
            <td>N/A</td>
        </tr>
        <tr>
            <td>Field 7</td>
            <td>N/A</td>
            <td>N/A</td>
        </tr>
        <tr>
            <td>Field 8</td>
            <td>N/A</td>
            <td>N/A</td>
        </tr>
        <tr>
            <td>Field 9</td>
            <td>N/A</td>
            <td>N/A</td>
        </tr>
        <tr>
            <td>Field 10</td>
            <td>N/A</td>
            <td>N/A</td>
        </tr>
        <tr>
            <td>Field 11</td>
            <td>N/A</td>
            <td>N/A</td>
        </tr>
        <tr>
            <td>Field 12</td>
            <td>N/A</td>
            <td>N/A</td>
        </tr>
        <tr>
            <td>Field 13</td>
            <td>N/A</td>
            <td>N/A</td>
        </tr>
    </tbody>
</table>

## Event Data 2

| Field                      | Description                                                             |
| -------------------------- | ----------------------------------------------------------------------- |
| Field 1                    | 506                                                                     |
| Company Name               | The company name.                                                       |
| Size                       | The file size                                                           |
| Hash Type                  | The hash algorithm used:<br><br>0 = MD5<br>1 = SHA-1<br>2 = SHA-256     |
| Hash                       | The hash for this application.                                          |
| Product Version            | The application version.                                                |
| Field 7                    | Will require further investigation as to the purpose of this log entry. |
| Field 8                    | Will require further investigation as to the purpose of this log entry. |
| Field 9                    | Will require further investigation as to the purpose of this log entry. | 
| Field 10                   | Will require further investigation as to the purpose of this log entry. |
| Field 11                   | Will require further investigation as to the purpose of this log entry. |
| Field 12                   | Will require further investigation as to the purpose of this log entry. |
| Product Name               | The application name.                                                   |
| Field 14                   | Will require further investigation as to the purpose of this log entry. |
| Field 15                   | Will require further investigation as to the purpose of this log entry. |
| Field 16                   | Will require further investigation as to the purpose of this log entry. |
| Field 17                   | Will require further investigation as to the purpose of this log entry. |