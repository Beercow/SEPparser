VBN_DEF = """

typedef struct _VBN_METADATA_V1{
    int32 QM_HEADER_Offset;
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
    int32 Quarantine_Data_Size;
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
    int32 QM_HEADER_Offset;
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
    int32 Quarantine_Data_Size;
    int32 Date_Accessed_2;
    int32 Unknown4;
    int32 Date_Modified_2;
    int32 Unknown5;
    int32 Date_Created_2;
    int32 Unknown6;
    int32 VBin_Time_2;
    int32 Unknown7;
    int32 Unknown8;
    char Unique_ID[16];
    char Unknown9[260];
    int32 Unknown10;
    int32 Record_Type;
    uint32 Quarantine_Session_ID;
    int32 Remediation_Type;
    int32 Unknown11;
    int32 Unknown12;
    int32 Unknown13;
    int32 Unknown14;
    int32 Unknown15;
    int32 Unknown16;
    int32 Unknown17;
    wchar WDescription[384];
    char Unknown18[212];
} VBN_METADATA_V2;

typedef struct _VBN_METADATA_Linux{
    int32 QM_HEADER_Offset;
    char Description[4096];
    char Log_line[1112];
    int32 Flags; //if 0x2 contains dates, if 0x1 no dates
    uint32 Record_ID;
    char Unknown1[36];
    int32 Quarantine_Data_Size;
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
    char Unknown3[16];
    char Unknown4[36];
    int32 Quarantine_Data_Size_2;
    int32 Date_Modified_2;
    int32 Date_Created_2;
    int32 Date_Accessed_2;
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

typedef struct _VBN_METADATA_Linux_V2{
    int32 QM_HEADER_Offset;
    char Description[4096];
    char Log_line[1112];
    int32 Flags; //if 0x2 contains dates, if 0x1 no dates
    uint32 Record_ID;
    char Unknown1[40];
    int32 Quarantine_Data_Size;
    int32 Unknown2;
    int32 Date_Modified;
    int32 Date_Created;
    int32 Date_Accessed;
    int32 VBin_Time;
    int32 Data_Type1; //if 0x2 contains storage info, if 0x0 no storage info
    char Unknown3[444];
    char Storage_Name[48];
    int32 Storage_Instance_ID;
    char Storage_Key[4096];
    int32 Data_Type2;
    int32 Unknown4;
    char Unknown5[44];
    int32 Data_Type3;
    int32 Unknown6;
    int32 Quarantine_Data_Size_2;
    int32 Unknown7;
    int32 Date_Modified_2;
    int32 Date_Created_2;
    int32 Date_Accessed_2;
    int32 VBin_Time_2;
    char Unknown8[8];
    char Unique_ID[16];
    char Unknown9[4096];
    int32 Unknown10;
    int32 Record_Type;
    int32 Quarantine_Session_ID;
    int32 Remediation_Type;
    int32 Unknown11;
    int32 Unknown12;
    int32 Unknown13;
    int32 Unknown14;
    int32 Unknown15;
    int32 Unknown16;
    int32 Unknown17;
    wchar WDescription[384];
    char Unknown18[212];
} VBN_METADATA_Linux_V2;

typedef struct _QData_Location {
    int64 Header;
    int64 Quarantine_Data_Offset;
    int64 QData_Location_Size;
    int32 QData_Info_Size;
    char Unknown15[Quarantine_Data_Offset -28];
} QData_Location;

typedef struct _QData_Info {
    int64 QData_Info_Header;
    int64 QData_Info_Size;
    char QData[QData_Info_Size -16];
} QData_Info;

typedef struct _Quarantine_Metadata_Header {
    int64 QM_Header;
    int64 QM_Header_Size;
    int64 QM_Size;
    int64 QM_Size_Header_Size;
    int64 End_of_QM_to_End_of_VBN;
} Quarantine_Metadata_Header;

typedef struct _Quarantine_Hash {
    BYTE Tag1;
    int32 Tag1_Data;
    BYTE Tag2;
    BYTE Tag2_Data;
} Quarantine_Hash;

typedef struct _Quarantine_Hash_Continued {
    BYTE Tag3;
    int32 SHA1_Hash_Length;
    wchar SHA1[SHA1_Hash_Length/2];
    BYTE Tag4;
    int32 Tag4_Data;
    BYTE Tag5;
    int32 Tag5_Data;
    BYTE Tag6;
    int32 QFS_Size;
    char Quarantine_Data_Size_2[QFS_Size];
} Quarantine_Hash_Continued;

typedef struct _Quarantine_SDDL {
    BYTE Tag7;
    int32 Security_Descriptor_Size;
    wchar Security_Descriptor[Security_Descriptor_Size/2];
    BYTE Tag8;
    int32 Tag8_Data;
    BYTE Tag9;
    int64 Quarantine_Data_Size_3;
} Quarantine_SDDL;

typedef struct _Chunk {
    BYTE Data_Type;
    int32 Chunk_Size;
} Chunk;

typedef struct _Unknown_Header {
    int64 Unknown15;
    int32 Size;
    int64 Unknown16;
    char Unknown17[Size];
    int64 Unknown18;
    int32 Quarantine_Data_Size;
    int64 Unknown19;
} Unknown_Header;

typedef struct _Extended_Attribute {
    int64 Attribute_type;
    int64 Attribute_Size;
    int32 Attribute_Name_Size;
} Extended_Attribute;

typedef struct _FILE_FULL_EA_INFORMATION {
  ULONG  NextEntryOffset;
  UCHAR  Flags;
  UCHAR  EaNameLength;
  USHORT EaValueLength;
  char   EaName[EaNameLength];
  char   EaValue[EaValueLength + 1];
} FILE_FULL_EA_INFORMATION;

typedef struct _ADS_Attribute {
    int64 Attribute_Type;
    int64 Attribute_Size;
    int32 Attribute_Name_Size;
    char ADS_Name[Attribute_Name_Size];
    char Data[Attribute_Size];
} ADS_Attribute;

typedef struct _OBJECT_ID_Attribute {
    int64 Attribute_Type;
    int64 Attribute_Size;
    int32 Attribute_Name_Size;
    char GUID_Object_Id[16];
    char GUID_Birth_Volume_Id[16];
    char GUID_Birth_Object_Id[16];
    char GUID_Domain_Id[16];
} OBJECT_ID_Attribute;

typedef struct _Unknown_Attribute {
    int64 Data_Type;
    int64 Data_Size;
    int32 Name_Size;
    char Name[Name_Size];
    char Data[Data_Size];
} Unknown_Attribute;

"""

ASN1_DEF = """

typedef struct _ASN1_HEADER {
    BYTE Tag1;
    int32 Value1;
    BYTE Tag2;
    int32 Size;
} ASN1_HEADER;

typedef struct _IDSxpx86_HEADER {
    BYTE Tag1;
    int32 Value1;
    BYTE Tag2;
    char GUID1[16];
    BYTE Tag3;
    char GUID2[16];
    BYTE Tag4;
    int32 Value2;
    BYTE Tag5;
    int32 Value3;
} IDSxpx86_HEADER;

typedef struct _BHSvcPlg_HEADER {
    BYTE Tag1;
    int32 Data_Length;
    BYTE Tag2;
    char GUID[16];
} BHSvcPlg_HEADER;

typedef struct _ASN1_List_Header {
    BYTE Type1;
    long Value1;
    BYTE Type2;
    BYTE Value2;
    BYTE Type3;
    BYTE Value3;
    BYTE Type4;
    long Value4;
    BYTE Type5;
    long Entries;
} ASN1_List_Header;

typedef struct _ASN1_List_Entry {
    BYTE Tag1;
    long ID;
    BYTE Tag2;
    BYTE Content_Type;
} ASN1_List_Entry;

typedef struct _ASN1_1 {
    BYTE Tag;
    BYTE Value;
} ASN1_1;

typedef struct _ASN1_2 {
    BYTE Tag;
    short Value;
} ASN1_2;

typedef struct _ASN1_4 {
    BYTE Tag;
    long Value;
} ASN1_4;

typedef struct _ASN1_8 {
    BYTE Tag;
    char Value[8];
} ASN1_8;

typedef struct _ASN1_16 {
    BYTE Tag;
    char GUID[16];
} ASN1_16;

typedef struct _ASN1_BLOB {
    BYTE Tag;
    int32 Data_Length;
    char BLOB[Data_Length];
} ASN1_BLOB;

typedef struct _ASN1_GUID {
    BYTE Tag;
    int32 Data_Length;
    char GUID[Data_Length];
} ASN1_GUID;

typedef struct _ID_0x07 {
    BYTE Tag;
    int32 Data_Length;
    BYTE Type1;
    long Value1;
    BYTE Type2;
    long Value2;
    BYTE Type3;
    int32 0x07_Data_Length;
    char StringA[0x07_Data_Length];
} ID_0x07;

typedef struct _ID_0x08 {
    BYTE Tag;
    int32 Data_Length;
    BYTE Type1;
    long Value1;
    BYTE Type2;
    long Value2;
    BYTE Type3;
    int32 0x08_Data_Length;
    wchar StringW[0x08_Data_Length/2];
} ID_0x08;

typedef struct _ID_0x08_2 {
    BYTE Tag;
    int32 Data_Length;
    BYTE Type1;
    long Value1;
    BYTE Type2;
    int32 0x08_Data_Length;
    wchar StringW[0x08_Data_Length/2];
} ID_0x08_2;

typedef struct _RAW_DATA {
    BYTE Tag1;
    int32 Data_Length1;
    BYTE Type;
    long Value;
    BYTE Tag2;
    int32 Data_Length2;
} RAW_DATA;

typedef struct _GUID_List_Header {
    BYTE Tag1;
    int32 Size;
    BYTE Tag2;
    int32 Value;
    BYTE Tag3;
    int32 Entries;
} GUID_List_Header;

typedef struct _ASN1_Unknown_Header {
    BYTE Tag1;
    int32 Value1;
    BYTE Tag2;
    char Value2[16];
    BYTE Tag3;
    BYTE Tag4;
    BYTE Tag5;
    int32 Value3;
    BYTE Tag6;
    BYTE Tag7;
} ASN1_Unknown_Header;

"""

bb811a3a8fc1be48822c8b6263a5204d_DEF = """

typedef struct _Header {
    BYTE Tag;
    int32 Data_Length1;
    int32 Unknown1;
    int32 Entries;
    int32 Data_Length2;
    int32 Unknown2;
} Header;

typedef struct _S0x01 {
    char Unknown[10];
} S0x01;

typedef struct _S0x03 {
    BYTE Tag;
    char Unknown[5];
    int32 Data;
} S0x03;

typedef struct _S0x04 {
    BYTE Tag;
    char Unknown[5];
    int64 Data;
} S0x04;

typedef struct _S0x05 {
    BYTE Tag;
    char Unknown[5];
    int32 Size;
    wchar StringW[Size/2];
} S0x05;

typedef struct _S0x06 {
    BYTE Tag;
    char Unknown[5];
    int32 Size;
    char String[Size];
} S0x06;

"""

b91f8a5cb7355c44980325fca1575e71_DEF = """
typedef struct _Header {
    BYTE Tag1;
    int32 Data_Length;
    char Unknown1[15];
} Header;

typedef struct _String {
    BYTE Tag;
    int32 Size;
    wchar StringW[Size/2];
} String;

typedef struct _ASN1_1 {
    BYTE Tag;
    BYTE Value;
} ASN1_1;

typedef struct _ASN1_4 {
    BYTE Tag;
    long Value;
} ASN1_4;

typedef struct _ASN1_8 {
    BYTE Tag;
    char Value[8];
} ASN1_8;

typedef struct _ASN1_Header {
    BYTE Tag1;
    int32 size;
    BYTE Tag2;
    long Unknown;
} ASN1_Header;

typedef struct _Data {
    BYTE Tag;
    int32 Size;
    char Blob[Size];
} Data;

"""
