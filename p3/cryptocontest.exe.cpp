// CUSTOM START
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <chrono>
unsigned char _data[0x10000]; // 140000000 ~
#define DAT_140004308 (*(_data + 0x4308))
#define DAT_140006008 (*(_data + 0x6008))
#define DAT_140006620 (*(_data + 0x6620))
#define DAT_140006630 (*(_data + 0x6630))
#define DAT_140006640 (*(_data + 0x6640))
#define DAT_140006650 (*(_data + 0x6650))
#define DAT_140006660 (*(_data + 0x6660))
#define DAT_140007030 (*(_data + 0x7030))
unsigned char _chacha20_ctx[0x50] = "chacha20";
//const char* s_chacha20_140004320 = "chacha20";
//#define PTR_s_chacha20_140004320 (*s_chacha20_140004320)
void zero16(void* buf) {
  for (int i = 0; i < 16; ++i) {
    ((unsigned char*)buf)[i] = 0;
  }
}
void zero8(void* buf) {
  for (int i = 0; i < 8; ++i) {
    ((unsigned char*)buf)[i] = 0;
  }
}
// CUSTOM END

typedef unsigned char   undefined;

typedef unsigned long long    GUID;

typedef unsigned char    byte;
typedef unsigned int    dword;
typedef long long    longlong;
typedef unsigned long long    qword;
typedef unsigned char    uchar;
typedef unsigned int    uint;
typedef unsigned long    ulong;
typedef unsigned long long    ulonglong;
typedef unsigned char    undefined1;
typedef unsigned short    undefined2;
typedef unsigned int    undefined4;
typedef unsigned long long    undefined8;
typedef unsigned short    ushort;
typedef unsigned short    wchar16;
typedef unsigned short    word;

// CUSTOM START
undefined8 FUN_140001ea0(undefined4 *param_1,undefined4 *param_2);
void FUN_1400020f0(byte *param_1,uint param_2,uint *param_3);
int FUN_140001b90(uint *param_1,uint *param_2,uint param_3,uint *param_4);
void FUN_140002530(longlong param_1);
void FUN_1400027f8(void);
void FUN_140002c70(void);

void fill16(void* buf, undefined4 a, undefined4 b, undefined4 c, undefined4 d) {
  ((undefined4*)buf)[0] = a;
  ((undefined4*)buf)[1] = b;
  ((undefined4*)buf)[2] = c;
  ((undefined4*)buf)[3] = d;
}

void UndefinedFunction_1400020c0(longlong param_1)

{
  *(undefined2 *)(param_1 + 0xb8) = 0;
  zero16((undefined (*) [16])(param_1 + 0x8c));
  zero16((undefined (*) [16])(param_1 + 0x9c));
  *(undefined8 *)(param_1 + 0xac) = 0;
  *(undefined4 *)(param_1 + 0xb4) = 0;
  return;
}
// CUSTOM END

typedef struct CLIENT_ID CLIENT_ID, *PCLIENT_ID;

struct CLIENT_ID {
    void * UniqueProcess;
    void * UniqueThread;
};

typedef struct _SYSTEM_INFO _SYSTEM_INFO, *P_SYSTEM_INFO;

typedef struct _SYSTEM_INFO * LPSYSTEM_INFO;

typedef union _union_552 _union_552, *P_union_552;

typedef ulong DWORD;

typedef void * LPVOID;

typedef ulonglong ULONG_PTR;

typedef ULONG_PTR DWORD_PTR;

typedef ushort WORD;

typedef struct _struct_553 _struct_553, *P_struct_553;

struct _struct_553 {
    WORD wProcessorArchitecture;
    WORD wReserved;
};

union _union_552 {
    DWORD dwOemId;
    struct _struct_553 s;
};

struct _SYSTEM_INFO {
    union _union_552 u;
    DWORD dwPageSize;
    LPVOID lpMinimumApplicationAddress;
    LPVOID lpMaximumApplicationAddress;
    DWORD_PTR dwActiveProcessorMask;
    DWORD dwNumberOfProcessors;
    DWORD dwProcessorType;
    DWORD dwAllocationGranularity;
    WORD wProcessorLevel;
    WORD wProcessorRevision;
};

typedef long LONG;

typedef struct _EXCEPTION_POINTERS _EXCEPTION_POINTERS, *P_EXCEPTION_POINTERS;

typedef LONG (* PTOP_LEVEL_EXCEPTION_FILTER)(struct _EXCEPTION_POINTERS *);

typedef struct _EXCEPTION_RECORD _EXCEPTION_RECORD, *P_EXCEPTION_RECORD;

typedef struct _EXCEPTION_RECORD EXCEPTION_RECORD;

typedef EXCEPTION_RECORD * PEXCEPTION_RECORD;

typedef struct _CONTEXT _CONTEXT, *P_CONTEXT;

typedef struct _CONTEXT * PCONTEXT;

typedef void * PVOID;

typedef ulonglong DWORD64;

typedef union _union_54 _union_54, *P_union_54;

typedef struct _M128A _M128A, *P_M128A;

typedef struct _M128A M128A;

typedef struct _XSAVE_FORMAT _XSAVE_FORMAT, *P_XSAVE_FORMAT;

typedef struct _XSAVE_FORMAT XSAVE_FORMAT;

typedef XSAVE_FORMAT XMM_SAVE_AREA32;

typedef struct _struct_55 _struct_55, *P_struct_55;

typedef ulonglong ULONGLONG;

typedef longlong LONGLONG;

typedef uchar BYTE;

struct _M128A {
    ULONGLONG Low;
    LONGLONG High;
};

struct _XSAVE_FORMAT {
    WORD ControlWord;
    WORD StatusWord;
    BYTE TagWord;
    BYTE Reserved1;
    WORD ErrorOpcode;
    DWORD ErrorOffset;
    WORD ErrorSelector;
    WORD Reserved2;
    DWORD DataOffset;
    WORD DataSelector;
    WORD Reserved3;
    DWORD MxCsr;
    DWORD MxCsr_Mask;
    M128A FloatRegisters[8];
    M128A XmmRegisters[16];
    BYTE Reserved4[96];
};

struct _struct_55 {
    M128A Header[2];
    M128A Legacy[8];
    M128A Xmm0;
    M128A Xmm1;
    M128A Xmm2;
    M128A Xmm3;
    M128A Xmm4;
    M128A Xmm5;
    M128A Xmm6;
    M128A Xmm7;
    M128A Xmm8;
    M128A Xmm9;
    M128A Xmm10;
    M128A Xmm11;
    M128A Xmm12;
    M128A Xmm13;
    M128A Xmm14;
    M128A Xmm15;
};

union _union_54 {
    XMM_SAVE_AREA32 FltSave;
    struct _struct_55 s;
};

struct _CONTEXT {
    DWORD64 P1Home;
    DWORD64 P2Home;
    DWORD64 P3Home;
    DWORD64 P4Home;
    DWORD64 P5Home;
    DWORD64 P6Home;
    DWORD ContextFlags;
    DWORD MxCsr;
    WORD SegCs;
    WORD SegDs;
    WORD SegEs;
    WORD SegFs;
    WORD SegGs;
    WORD SegSs;
    DWORD EFlags;
    DWORD64 Dr0;
    DWORD64 Dr1;
    DWORD64 Dr2;
    DWORD64 Dr3;
    DWORD64 Dr6;
    DWORD64 Dr7;
    DWORD64 Rax;
    DWORD64 Rcx;
    DWORD64 Rdx;
    DWORD64 Rbx;
    DWORD64 Rsp;
    DWORD64 Rbp;
    DWORD64 Rsi;
    DWORD64 Rdi;
    DWORD64 R8;
    DWORD64 R9;
    DWORD64 R10;
    DWORD64 R11;
    DWORD64 R12;
    DWORD64 R13;
    DWORD64 R14;
    DWORD64 R15;
    DWORD64 Rip;
    union _union_54 u;
    M128A VectorRegister[26];
    DWORD64 VectorControl;
    DWORD64 DebugControl;
    DWORD64 LastBranchToRip;
    DWORD64 LastBranchFromRip;
    DWORD64 LastExceptionToRip;
    DWORD64 LastExceptionFromRip;
};

struct _EXCEPTION_RECORD {
    DWORD ExceptionCode;
    DWORD ExceptionFlags;
    struct _EXCEPTION_RECORD * ExceptionRecord;
    PVOID ExceptionAddress;
    DWORD NumberParameters;
    ULONG_PTR ExceptionInformation[15];
};

struct _EXCEPTION_POINTERS {
    PEXCEPTION_RECORD ExceptionRecord;
    PCONTEXT ContextRecord;
};

typedef PTOP_LEVEL_EXCEPTION_FILTER LPTOP_LEVEL_EXCEPTION_FILTER;

typedef struct _RUNTIME_FUNCTION _RUNTIME_FUNCTION, *P_RUNTIME_FUNCTION;

struct _RUNTIME_FUNCTION {
    DWORD BeginAddress;
    DWORD EndAddress;
    DWORD UnwindData;
};

typedef struct _RUNTIME_FUNCTION * PRUNTIME_FUNCTION;

typedef struct _UNWIND_HISTORY_TABLE_ENTRY _UNWIND_HISTORY_TABLE_ENTRY, *P_UNWIND_HISTORY_TABLE_ENTRY;

typedef struct _UNWIND_HISTORY_TABLE_ENTRY UNWIND_HISTORY_TABLE_ENTRY;

struct _UNWIND_HISTORY_TABLE_ENTRY {
    DWORD64 ImageBase;
    PRUNTIME_FUNCTION FunctionEntry;
};

typedef union _union_61 _union_61, *P_union_61;

typedef struct _M128A * PM128A;

typedef struct _struct_62 _struct_62, *P_struct_62;

struct _struct_62 {
    PM128A Xmm0;
    PM128A Xmm1;
    PM128A Xmm2;
    PM128A Xmm3;
    PM128A Xmm4;
    PM128A Xmm5;
    PM128A Xmm6;
    PM128A Xmm7;
    PM128A Xmm8;
    PM128A Xmm9;
    PM128A Xmm10;
    PM128A Xmm11;
    PM128A Xmm12;
    PM128A Xmm13;
    PM128A Xmm14;
    PM128A Xmm15;
};

union _union_61 {
    PM128A FloatingContext[16];
    struct _struct_62 s;
};

typedef union _union_63 _union_63, *P_union_63;

typedef ulonglong * PDWORD64;

typedef struct _struct_64 _struct_64, *P_struct_64;

struct _struct_64 {
    PDWORD64 Rax;
    PDWORD64 Rcx;
    PDWORD64 Rdx;
    PDWORD64 Rbx;
    PDWORD64 Rsp;
    PDWORD64 Rbp;
    PDWORD64 Rsi;
    PDWORD64 Rdi;
    PDWORD64 R8;
    PDWORD64 R9;
    PDWORD64 R10;
    PDWORD64 R11;
    PDWORD64 R12;
    PDWORD64 R13;
    PDWORD64 R14;
    PDWORD64 R15;
};

union _union_63 {
    PDWORD64 IntegerContext[16];
    struct _struct_64 s;
};

typedef enum _EXCEPTION_DISPOSITION {
    ExceptionContinueExecution=0,
    ExceptionContinueSearch=1,
    ExceptionNestedException=2,
    ExceptionCollidedUnwind=3
} _EXCEPTION_DISPOSITION;

typedef enum _EXCEPTION_DISPOSITION EXCEPTION_DISPOSITION;

typedef EXCEPTION_DISPOSITION (EXCEPTION_ROUTINE)(struct _EXCEPTION_RECORD *, PVOID, struct _CONTEXT *, PVOID);

typedef struct _UNWIND_HISTORY_TABLE _UNWIND_HISTORY_TABLE, *P_UNWIND_HISTORY_TABLE;

struct _UNWIND_HISTORY_TABLE {
    DWORD Count;
    BYTE LocalHint;
    BYTE GlobalHint;
    BYTE Search;
    BYTE Once;
    DWORD64 LowAddress;
    DWORD64 HighAddress;
    UNWIND_HISTORY_TABLE_ENTRY Entry[12];
};

typedef wchar_t WCHAR;

typedef struct _KNONVOLATILE_CONTEXT_POINTERS _KNONVOLATILE_CONTEXT_POINTERS, *P_KNONVOLATILE_CONTEXT_POINTERS;

struct _KNONVOLATILE_CONTEXT_POINTERS {
    union _union_61 u;
    union _union_63 u2;
};

typedef union _LARGE_INTEGER _LARGE_INTEGER, *P_LARGE_INTEGER;

typedef struct _struct_19 _struct_19, *P_struct_19;

typedef struct _struct_20 _struct_20, *P_struct_20;

struct _struct_20 {
    DWORD LowPart;
    LONG HighPart;
};

struct _struct_19 {
    DWORD LowPart;
    LONG HighPart;
};

union _LARGE_INTEGER {
    struct _struct_19 s;
    struct _struct_20 u;
    LONGLONG QuadPart;
};

typedef union _LARGE_INTEGER LARGE_INTEGER;

typedef WCHAR * LPCWSTR;

typedef struct _UNWIND_HISTORY_TABLE * PUNWIND_HISTORY_TABLE;

typedef void * HANDLE;

typedef struct _KNONVOLATILE_CONTEXT_POINTERS * PKNONVOLATILE_CONTEXT_POINTERS;

typedef EXCEPTION_ROUTINE * PEXCEPTION_ROUTINE;

typedef struct IMAGE_DOS_HEADER IMAGE_DOS_HEADER, *PIMAGE_DOS_HEADER;

struct IMAGE_DOS_HEADER {
    char e_magic[2]; // Magic number
    word e_cblp; // Bytes of last page
    word e_cp; // Pages in file
    word e_crlc; // Relocations
    word e_cparhdr; // Size of header in paragraphs
    word e_minalloc; // Minimum extra paragraphs needed
    word e_maxalloc; // Maximum extra paragraphs needed
    word e_ss; // Initial (relative) SS value
    word e_sp; // Initial SP value
    word e_csum; // Checksum
    word e_ip; // Initial IP value
    word e_cs; // Initial (relative) CS value
    word e_lfarlc; // File address of relocation table
    word e_ovno; // Overlay number
    word e_res[4][4]; // Reserved words
    word e_oemid; // OEM identifier (for e_oeminfo)
    word e_oeminfo; // OEM information; e_oemid specific
    word e_res2[10][10]; // Reserved words
    dword e_lfanew; // File address of new exe header
    byte e_program[64]; // Actual DOS program
};

typedef struct DotNetPdbInfo DotNetPdbInfo, *PDotNetPdbInfo;

struct DotNetPdbInfo {
    char signature[4];
    GUID guid;
    dword age;
    char pdbpath[36];
};

typedef struct _FILETIME _FILETIME, *P_FILETIME;

typedef struct _FILETIME * LPFILETIME;

struct _FILETIME {
    DWORD dwLowDateTime;
    DWORD dwHighDateTime;
};

typedef struct HINSTANCE__ HINSTANCE__, *PHINSTANCE__;

struct HINSTANCE__ {
    int unused;
};

typedef struct HINSTANCE__ * HINSTANCE;

typedef HINSTANCE HMODULE;

typedef int BOOL;

typedef struct IMAGE_RESOURCE_DIRECTORY_ENTRY_NameStruct IMAGE_RESOURCE_DIRECTORY_ENTRY_NameStruct, *PIMAGE_RESOURCE_DIRECTORY_ENTRY_NameStruct;

struct IMAGE_RESOURCE_DIRECTORY_ENTRY_NameStruct {
    dword NameOffset;
    dword NameIsString;
};

typedef struct IMAGE_LOAD_CONFIG_CODE_INTEGRITY IMAGE_LOAD_CONFIG_CODE_INTEGRITY, *PIMAGE_LOAD_CONFIG_CODE_INTEGRITY;

struct IMAGE_LOAD_CONFIG_CODE_INTEGRITY {
    word Flags;
    word Catalog;
    dword CatalogOffset;
    dword Reserved;
};

typedef struct IMAGE_DEBUG_DIRECTORY IMAGE_DEBUG_DIRECTORY, *PIMAGE_DEBUG_DIRECTORY;

struct IMAGE_DEBUG_DIRECTORY {
    dword Characteristics;
    dword TimeDateStamp;
    word MajorVersion;
    word MinorVersion;
    dword Type;
    dword SizeOfData;
    dword AddressOfRawData;
    dword PointerToRawData;
};

typedef struct IMAGE_FILE_HEADER IMAGE_FILE_HEADER, *PIMAGE_FILE_HEADER;

struct IMAGE_FILE_HEADER {
    word Machine; // 34404
    word NumberOfSections;
    dword TimeDateStamp;
    dword PointerToSymbolTable;
    dword NumberOfSymbols;
    word SizeOfOptionalHeader;
    word Characteristics;
};

typedef struct IMAGE_LOAD_CONFIG_DIRECTORY64 IMAGE_LOAD_CONFIG_DIRECTORY64, *PIMAGE_LOAD_CONFIG_DIRECTORY64;

typedef enum IMAGE_GUARD_FLAGS {
    IMAGE_GUARD_CF_INSTRUMENTED=256,
    IMAGE_GUARD_CFW_INSTRUMENTED=512,
    IMAGE_GUARD_CF_FUNCTION_TABLE_PRESENT=1024,
    IMAGE_GUARD_SECURITY_COOKIE_UNUSED=2048,
    IMAGE_GUARD_PROTECT_DELAYLOAD_IAT=4096,
    IMAGE_GUARD_DELAYLOAD_IAT_IN_ITS_OWN_SECTION=8192,
    IMAGE_GUARD_CF_EXPORT_SUPPRESSION_INFO_PRESENT=16384,
    IMAGE_GUARD_CF_ENABLE_EXPORT_SUPPRESSION=32768,
    IMAGE_GUARD_CF_LONGJUMP_TABLE_PRESENT=65536,
    IMAGE_GUARD_RF_INSTRUMENTED=131072,
    IMAGE_GUARD_RF_ENABLE=262144,
    IMAGE_GUARD_RF_STRICT=524288,
    IMAGE_GUARD_CF_FUNCTION_TABLE_SIZE_MASK_1=268435456,
    IMAGE_GUARD_CF_FUNCTION_TABLE_SIZE_MASK_2=536870912,
    IMAGE_GUARD_CF_FUNCTION_TABLE_SIZE_MASK_4=1073741824,
    IMAGE_GUARD_CF_FUNCTION_TABLE_SIZE_MASK_8=2147483648
} IMAGE_GUARD_FLAGS;



typedef struct IMAGE_SECTION_HEADER IMAGE_SECTION_HEADER, *PIMAGE_SECTION_HEADER;

typedef union Misc Misc, *PMisc;

typedef enum SectionFlags {
    IMAGE_SCN_TYPE_NO_PAD=8,
    IMAGE_SCN_RESERVED_0001=16,
    IMAGE_SCN_CNT_CODE=32,
    IMAGE_SCN_CNT_INITIALIZED_DATA=64,
    IMAGE_SCN_CNT_UNINITIALIZED_DATA=128,
    IMAGE_SCN_LNK_OTHER=256,
    IMAGE_SCN_LNK_INFO=512,
    IMAGE_SCN_RESERVED_0040=1024,
    IMAGE_SCN_LNK_REMOVE=2048,
    IMAGE_SCN_LNK_COMDAT=4096,
    IMAGE_SCN_GPREL=32768,
    IMAGE_SCN_MEM_16BIT=131072,
    IMAGE_SCN_MEM_PURGEABLE=131072,
    IMAGE_SCN_MEM_LOCKED=262144,
    IMAGE_SCN_MEM_PRELOAD=524288,
    IMAGE_SCN_ALIGN_1BYTES=1048576,
    IMAGE_SCN_ALIGN_2BYTES=2097152,
    IMAGE_SCN_ALIGN_4BYTES=3145728,
    IMAGE_SCN_ALIGN_8BYTES=4194304,
    IMAGE_SCN_ALIGN_16BYTES=5242880,
    IMAGE_SCN_ALIGN_32BYTES=6291456,
    IMAGE_SCN_ALIGN_64BYTES=7340032,
    IMAGE_SCN_ALIGN_128BYTES=8388608,
    IMAGE_SCN_ALIGN_256BYTES=9437184,
    IMAGE_SCN_ALIGN_512BYTES=10485760,
    IMAGE_SCN_ALIGN_1024BYTES=11534336,
    IMAGE_SCN_ALIGN_2048BYTES=12582912,
    IMAGE_SCN_ALIGN_4096BYTES=13631488,
    IMAGE_SCN_ALIGN_8192BYTES=14680064,
    IMAGE_SCN_LNK_NRELOC_OVFL=16777216,
    IMAGE_SCN_MEM_DISCARDABLE=33554432,
    IMAGE_SCN_MEM_NOT_CACHED=67108864,
    IMAGE_SCN_MEM_NOT_PAGED=134217728,
    IMAGE_SCN_MEM_SHARED=268435456,
    IMAGE_SCN_MEM_EXECUTE=536870912,
    IMAGE_SCN_MEM_READ=1073741824,
    IMAGE_SCN_MEM_WRITE=2147483648
} SectionFlags;

union Misc {
    dword PhysicalAddress;
    dword VirtualSize;
};



typedef struct _iobuf _iobuf, *P_iobuf;

struct _iobuf {
    char * _ptr;
    int _cnt;
    char * _base;
    int _flag;
    int _file;
    int _charbuf;
    int _bufsiz;
    char * _tmpfname;
};

typedef int (* _onexit_t)(void);

typedef longlong __time64_t;

typedef int errno_t;




undefined * FUN_140001000(void)

{
  return &DAT_140007030;
}



//void FUN_140001010(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4)
void FUN_140001010()

{
  fprintf(stderr, "[%s:%d:%s] not implemented", __FILE__, __LINE__, __FUNCTION__);
  //undefined8 uVar1;
  //undefined8 *puVar2;
  //undefined8 local_res10;
  //undefined8 local_res18;
  //undefined8 local_res20;
  
  //local_res10 = param_2;
  //local_res18 = param_3;
  //local_res20 = param_4;
  //uVar1 = __acrt_iob_func(1);
  //puVar2 = (undefined8 *)FUN_140001000();
  //__stdio_common_vfprintf(*puVar2,uVar1,param_1,0,&local_res10);
  //return;
}



int FUN_140001070(uint *param_1,int *param_2)

{
  longlong lVar1;
  char cVar2;
  int iVar3;
  longlong *plVar4;
  longlong lVar5;
  undefined8 uVar6;
  undefined8 *_Memory;
  int iVar7;
  int iVar8;
  byte *pbVar9;
  undefined (*pauVar10) [16];
  undefined4 extraout_XMM0_Da;
  undefined4 extraout_XMM0_Db;
  undefined4 extraout_XMM0_Dc;
  undefined4 extraout_XMM0_Dd;
  undefined auStack_78 [32];
  byte local_58 [40];
  ulonglong local_30;

  static int count = 0;
  
  local_30 = DAT_140006008 ^ (ulonglong)auStack_78;
  iVar8 = 0;
  iVar7 = iVar8;
  do {
    //iVar3 = memcmp(*(void**)(&DAT_140006620 + (longlong)iVar7 * 10),_chacha20_ctx,0x50);
    iVar3 = 0;
    iVar7 = count++;
    if (iVar3 == 0) goto LAB_14000113d;
    iVar7 = iVar7 + 1;
  } while (iVar7 < 0x20);
  plVar4 = (longlong*)&DAT_140006620;
  iVar7 = iVar8;
  do {
    if (*plVar4 == 0) {
      lVar5 = (longlong)iVar7;
      lVar1 = lVar5 * 0x50;
      //*(undefined4 *)(&DAT_140006620 + lVar5 * 10) = 0x400043b0;
      //*(undefined4 *)((longlong)&DAT_140006620 + lVar1 + 4) = 1;
      //*(undefined4 *)(lVar1 + 0x140006628) = 0x28;
      //*(undefined4 *)(lVar1 + 0x14000662c) = 0;
      //*(void**)(&DAT_140006620 + 0x00) = (void*)s_chacha20_140004320;
      *(void**)(&DAT_140006620 + 0x00) = (void*)0;
      *(void**)(&DAT_140006620 + 0x08) = (void*)0x28;
      lVar1 = lVar5 * 0x50;
      //*(undefined4 *)(&DAT_140006630 + lVar1) = 0x400020c0;
      //*(undefined4 *)(lVar1 + 0x140006634) = 1;
      //*(undefined4 *)(lVar1 + 0x140006638) = 0x400020f0;
      //*(undefined4 *)(lVar1 + 0x14000663c) = 1;
      *(void**)(&DAT_140006620 + 0x10) = (void*)UndefinedFunction_1400020c0;
      *(void**)(&DAT_140006620 + 0x18) = (void*)FUN_1400020f0;
      lVar1 = lVar5 * 0x50;
      //*(undefined4 *)(&DAT_140006640 + lVar1) = 0x400022b0;
      //*(undefined4 *)(lVar1 + 0x140006644) = 1;
      //*(undefined4 *)(lVar1 + 0x140006648) = 0x40002390;
      //*(undefined4 *)(lVar1 + 0x14000664c) = 1;
      //*(void**)(&DAT_140006620 + 0x20) = (void*)FUN_1400022b0;
      //*(void**)(&DAT_140006620 + 0x28) = (void*)FUN_140002390;
      *(void**)(&DAT_140006620 + 0x20) = (void*)0;
      *(void**)(&DAT_140006620 + 0x28) = (void*)0;
      lVar1 = lVar5 * 0x50;
      //*(undefined4 *)(&DAT_140006650 + lVar1) = 0x40002410;
      //*(undefined4 *)(lVar1 + 0x140006654) = 1;
      //*(undefined4 *)(lVar1 + 0x140006658) = 0x40002450;
      //*(undefined4 *)(lVar1 + 0x14000665c) = 1;
      //*(void**)(&DAT_140006620 + 0x30) = (void*)FUN_140002410;
      //*(void**)(&DAT_140006620 + 0x3c) = (void*)FUN_140002450;
      *(void**)(&DAT_140006620 + 0x30) = (void*)0;
      *(void**)(&DAT_140006620 + 0x38) = (void*)0;
      lVar5 = lVar5 * 0x50;
      //*(undefined4 *)(&DAT_140006660 + lVar5) = 0x400024e0;
      //*(undefined4 *)(lVar5 + 0x140006664) = 1;
      //*(undefined4 *)(lVar5 + 0x140006668) = 0;
      //*(undefined4 *)(lVar5 + 0x14000666c) = 0;
      //*(void**)(&DAT_140006620 + 0x40) = (void*)FUN_1400024e0;
      //*(void**)(&DAT_140006620 + 0x48) = (void*)0;
      *(void**)(&DAT_140006620 + 0x40) = (void*)0;
      *(void**)(&DAT_140006620 + 0x48) = (void*)0;
LAB_14000113d:
      *param_2 = iVar7;
      if (iVar7 != -1) {
        *(undefined2 *)(param_1 + 0x2e) = 0;
        pauVar10 = (undefined (*) [16])(param_1 + 0x23);
        //*pauVar10 = ZEXT816(0);
        zero16(pauVar10);
        //*(undefined (*) [16])(param_1 + 0x27) = ZEXT816(0);
        zero16((undefined (*) [16])(param_1 + 0x27));
        *(undefined8 *)(param_1 + 0x2b) = 0;
        param_1[0x2d] = 0;
        if ((*(short *)(param_1 + 0x2e) == 0) &&
           (uVar6 = FUN_140001ea0(param_1,(undefined4 *)pauVar10), (int)uVar6 == 0)) {
          *(undefined8 *)(param_1 + 0xc) = 0;
          param_1[0xe] = param_1[0x2b];
          param_1[0x20] = 0;
          param_1[0x21] = 8;
          param_1[0xf] = param_1[0x2c];
          //*pauVar10 = CONCAT412(extraout_XMM0_Dd,
          //                      CONCAT48(extraout_XMM0_Dc,
          //                               CONCAT44(extraout_XMM0_Db,extraout_XMM0_Da)));
          fill16(pauVar10, extraout_XMM0_Da, extraout_XMM0_Db, extraout_XMM0_Dc, extraout_XMM0_Dd);
          //pauVar10[1] = CONCAT412(extraout_XMM0_Dd,
          //                        CONCAT48(extraout_XMM0_Dc,
          //                                 CONCAT44(extraout_XMM0_Db,extraout_XMM0_Da)));
          fill16(pauVar10 + 1, extraout_XMM0_Da, extraout_XMM0_Db, extraout_XMM0_Dc, extraout_XMM0_Dd);
          *(undefined8 *)pauVar10[2] = 0;
          *(undefined2 *)(param_1 + 0x2e) = 1;
          param_1[0x2d] = 0;
        }
        pbVar9 = local_58;
        do {
          iVar7 = rand();
          cVar2 = (char)iVar8;
          iVar8 = iVar8 + 1;
          *pbVar9 = (char)iVar7 * (cVar2 + '\x01' + *(char *)param_2);
          pbVar9 = pbVar9 + 1;
        } while (iVar8 < 0x28);
        FUN_1400020f0(local_58,0x28,param_1);
        iVar7 = rand();
        _Memory = (undefined8 *)malloc((longlong)(iVar7 % 0x100 + 9));
        if ((_Memory != (undefined8 *)0x0) && (*(short *)(param_1 + 0x2e) != 0)) {
          *_Memory = 0;
          FUN_140001b90(param_1,(uint *)_Memory,8,(uint *)_Memory); // 여기서 8byte가 짤림;
        }
        free(_Memory);
      }
      goto LAB_1400012d7;
    }
    iVar7 = iVar7 + 1;
    plVar4 = plVar4 + 10;
  } while ((longlong)plVar4 < 0x140007020);
  *param_2 = -1;
LAB_1400012d7:
  FUN_140002530(local_30 ^ (ulonglong)auStack_78);
  return 1; // TODO assume always success
}



void FUN_1400012f0()

{
  undefined8 param_3;
  uint *param_4;
  uint uVar1;
  uint uVar2;
  int iVar3;
  FILE *pFVar4;
  ulonglong uVar5;
  uint *puVar6;
  void *pvVar7;
  longlong lVar8;
  FILE *_File;
  ulonglong uVar9;
  uint uVar10;
  longlong lVar11;
  longlong lVar12;
  ulonglong uVar13;
  undefined auStack_1a8 [32];
  int local_188;
  byte local_184 [4];
  _SYSTEM_INFO local_180;
  uint local_148 [48];
  undefined local_88 [8];
  uint auStack_80 [2];
  undefined local_78 [16];
  uint auStack_60 [2];
  uint auStack_40 [2];
  ulonglong local_28;

  undefined local_68 [16];
  undefined local_58 [16];
  undefined local_48 [16];
  undefined local_38 [16];
  
  printf("local_68 = %p\n", local_68);
  printf("local_58 = %p\n", local_58);
  printf("local_48 = %p\n", local_48);
  printf("local_38 = %p\n", local_38);
  
  local_28 = DAT_140006008 ^ (ulonglong)auStack_1a8;
  pFVar4 = fopen("c_contest_2024.jpg","rb");
  if (pFVar4 != (FILE *)0x0) {
    fclose(pFVar4);
    //uVar5 = _time64((__time64_t *)0x0);
    uVar5 = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count();
    srand((uint)uVar5 & 0xf0f0f0f0);
    //GetSystemInfo(&local_180);
    local_180.dwNumberOfProcessors = 64; // TODO(heehoon): arbitrary
    uVar13 = (ulonglong)(local_180.dwNumberOfProcessors + 0x10) * 0x44f0;
    uVar9 = uVar13 & 0xffffffff;
    if ((int)(uVar13 >> 0x20) != 0) {
      uVar9 = 0xffffffffffffffff;
    }
    puVar6 = (uint *)malloc(uVar9);
    uVar13 = (ulonglong)(local_180.dwNumberOfProcessors + 0x10) * 4;
    uVar9 = uVar13 & 0xffffffff;
    if ((int)(uVar13 >> 0x20) != 0) {
      uVar9 = 0xffffffffffffffff;
    }
    pvVar7 = malloc(uVar9);
    iVar3 = FUN_140001070(local_148,&local_188);
    if (iVar3 != 0) {
      uVar10 = 0;
      lVar11 = 0;
      do {
        iVar3 = FUN_140001070(puVar6 + (longlong)(int)uVar10 * 0x2f,
                              (int *)((longlong)pvVar7 + (longlong)(int)uVar10 * 4));
        if (iVar3 == 0) goto LAB_14000164d;
        unsigned char *buf = (unsigned char *)(puVar6 + (longlong)(int)uVar10 * 0x2f);
        printf("Iter %d, buf_addr = %p\n", uVar10, buf);
        for (int i = 0; i < 0x2f * 4; ++i) {
          printf("%02X ", buf[i]);
          if (i % 16 == 15) {
            printf("\n");
          }
        }
        printf("\n");
        uVar10 = uVar10 + 1;


      } while (uVar10 < 0x10);
      printf("puVar6 = %p, %d\n", puVar6, *(short *)(puVar6 + 0x2e));
      if ((puVar6 != (uint *)0x0) && (*(short *)(puVar6 + 0x2e) != 0)) {
        //_local_68 = ZEXT816(0);
        param_4 = (uint *)local_68;
        param_3 = 0x40;
        //local_58 = _local_68;
        zero16(&local_68);
        //_local_48 = _local_68;
        zero8(&local_48);
        //local_38 = _local_68;
        zero16(&local_38);
        FUN_140001b90(puVar6,(uint *)local_68,0x40,param_4);
        printf("local_68\n");
        for (int i = 0; i < 16; ++i) {
          printf("%02llX ", (ulonglong)(byte)local_68[i]);
        }
      }
      lVar12 = 0x10;
      do {
        lVar8 = lVar11;
        if ((puVar6 != (uint *)0x0) && (*(short *)(puVar6 + 0x2e) != 0)) {
          //_local_88 = ZEXT816(0);
          param_4 = (uint *)local_88;
          param_3 = 0x20;
          //local_78 = _local_88;
          zero16(&local_78);
          FUN_140001b90(puVar6,(uint *)local_88,0x20,param_4);
        }
        do {
          uVar10 = *(uint *)(local_88 + lVar8 + 4);
          uVar1 = *(uint *)(local_88 + lVar8 + 8);
          uVar2 = *(uint *)(local_88 + lVar8 + 0xc);
          *(uint *)(local_68 + lVar8) = *(uint *)(local_88 + lVar8) ^ *(uint *)(local_68 + lVar8);
          *(uint *)(local_68 + lVar8 + 4) = uVar10 ^ *(uint *)(local_68 + lVar8 + 4);
          *(uint *)(local_68 + lVar8 + 8) = uVar1 ^ *(uint *)(local_68 + lVar8 + 8);
          *(uint *)(local_68 + lVar8 + 0xc) = uVar2 ^ *(uint *)(local_68 + lVar8 + 0xc);
          lVar8 = lVar8 + 0x10;
        } while (lVar8 < 0x20);
        lVar8 = lVar11;
        if ((puVar6 != (uint *)0x0) && (*(short *)(puVar6 + 0x2e) != 0)) {
          //_local_88 = ZEXT816(0);
          param_4 = (uint *)local_88;
          param_3 = 0x20;
          //local_78 = _local_88;
          zero16(&local_78);
          FUN_140001b90(puVar6,(uint *)local_88,0x20,param_4);
        }
        do {
          uVar10 = *(uint *)(local_88 + lVar8 + 4);
          uVar1 = *(uint *)(local_88 + lVar8 + 8);
          uVar2 = *(uint *)(local_88 + lVar8 + 0xc);
          *(uint *)(local_48 + lVar8) = *(uint *)(local_88 + lVar8) ^ *(uint *)(local_48 + lVar8);
          *(uint *)(local_48 + lVar8 + 4) = uVar10 ^ *(uint *)(local_48 + lVar8 + 4);
          *(uint *)(local_48 + lVar8 + 8) = uVar1 ^ *(uint *)(local_48 + lVar8 + 8);
          *(uint *)(local_48 + lVar8 + 0xc) = uVar2 ^ *(uint *)(local_48 + lVar8 + 0xc);
          lVar8 = lVar8 + 0x10;
        } while (lVar8 < 0x20);
        puVar6 = puVar6 + 0x2f;
        lVar12 = lVar12 + -1;
      } while (lVar12 != 0);
      //FUN_140001010(&DAT_140004308,uVar5 & 0xffffffff,param_3,param_4);
      printf("%llu\n", uVar5);
      //do {
      //  //FUN_140001010("%02X ",(ulonglong)(byte)local_68[lVar11],param_3,param_4);
      //  FUN_140001010();
      //  lVar11 = lVar11 + 1;
      //} while (lVar11 < 0x40);
      for (int i = 0; i < 64; ++i) {
        printf("%02llX ", (ulonglong)(byte)local_68[i]);
      }
      puts("");
      pFVar4 = fopen("c_contest_2024.jpg","rb");
      _File = fopen("c_contest_2024_out.jpg","wb");
      if ((pFVar4 != (FILE *)0x0) && (_File != (FILE *)0x0)) {
        fseek(pFVar4,0,2);
        uVar10 = ftell(pFVar4);
        uVar13 = (ulonglong)uVar10;
        fseek(pFVar4,0,0);
        if (0 < (int)uVar10) {
          do {
            fread(local_184,1,1,pFVar4);
            uVar10 = rand();
            uVar10 = uVar10 & 0x8000003f;
            if ((int)uVar10 < 0) {
              uVar10 = (uVar10 - 1 | 0xffffffc0) + 1;
            }
            local_184[0] = local_184[0] ^ local_68[(int)uVar10];
            fwrite(local_184,1,1,_File);
            uVar13 = uVar13 - 1;
          } while (uVar13 != 0);
        }
        fclose(pFVar4);
        fclose(_File);
      }
    }
  }
LAB_14000164d:
  FUN_140002530(local_28 ^ (ulonglong)auStack_1a8);
  return;
}



// WARNING: Could not reconcile some variable overlaps

// param_1 next state
// param_2 current total state
// param_3 application number (0x14 == 20)
void FUN_140001670(undefined *param_1,uint *param_2,int param_3) {
  uint uVar1;
  uint uVar2;
  uint uVar3;
  uint uVar4;
  uint uVar5;
  uint uVar6;
  uint uVar7;
  uint uVar8;
  uint uVar9;
  uint uVar10;
  uint uVar11;
  uint uVar12;
  uint uVar13;
  uint local_d8;
  uint local_d4;
  uint local_d0;
  uint local_cc;
  int local_c8;
  uint local_c4;
  uint local_c0;
  uint local_bc;
  uint local_b8;
  uint local_b4;
  uint local_b0;
  uint local_ac;
  uint local_a8;
  uint local_a4;
  ulonglong local_a0;
  undefined *local_98;
  uint *local_90;
  undefined4 local_88;
  undefined4 uStack_84;
  undefined4 uStack_80;
  undefined4 uStack_7c;
  undefined4 local_78;
  undefined4 uStack_74;
  undefined4 uStack_70;
  undefined4 uStack_6c;
  undefined4 local_68;
  undefined4 uStack_64;
  undefined4 uStack_60;
  undefined4 uStack_5c;
  undefined4 local_58;
  undefined4 uStack_54;
  undefined4 uStack_50;
  undefined4 uStack_4c;
  ulonglong local_48;
  
  local_48 = DAT_140006008 ^ (ulonglong)&local_d8;
  uVar12 = param_2[4];
  uVar4 = param_2[5];
  uVar5 = param_2[6];
  uVar6 = param_2[7];
  uVar2 = *param_2;
  local_d8 = param_2[1];
  local_d4 = param_2[2];
  local_d0 = param_2[3];
  uVar7 = param_2[0xc];
  uVar9 = param_2[0xd];
  uVar11 = param_2[0xe];
  uVar3 = param_2[0xf];
  local_c4 = param_2[8];
  uVar1 = param_2[9];
  uVar10 = param_2[10];
  uVar8 = param_2[0xb];
  if (0 < param_3) {
    local_a0 = (ulonglong)((param_3 - 1U >> 1) + 1);
    local_c0 = uVar10;
    local_bc = uVar8;
    do {
      //uVar7 = uVar2 + uVar12 ^ uVar7;
      uVar7 = param_2[0] + param_2[4] ^ param_2[12];
      uVar8 = uVar7 << 0x10 | uVar7 >> 0x10;
      local_ac = uVar8 + local_c4;
      uVar10 = local_ac ^ uVar12;
      uVar10 = uVar10 << 0xc | uVar10 >> 0x14;
      uVar2 = uVar10 + uVar2 + uVar12;
      uVar8 = uVar2 ^ uVar8;
      uVar13 = uVar8 << 8 | uVar8 >> 0x18;
      local_ac = local_ac + uVar13;
      uVar10 = local_ac ^ uVar10;
      local_a8 = uVar10 << 7 | uVar10 >> 0x19;
      uVar9 = local_d8 + uVar4 ^ uVar9;
      uVar10 = uVar9 << 0x10 | uVar9 >> 0x10;
      uVar1 = uVar10 + uVar1;
      uVar8 = uVar1 ^ uVar4;
      uVar8 = uVar8 << 0xc | uVar8 >> 0x14;
      local_d8 = uVar8 + local_d8 + uVar4;
      uVar10 = local_d8 ^ uVar10;
      local_b0 = uVar10 << 8 | uVar10 >> 0x18;
      uVar1 = local_b0 + uVar1;
      uVar8 = uVar1 ^ uVar8;
      uVar7 = uVar8 << 7 | uVar8 >> 0x19;
      uVar11 = local_d4 + uVar5 ^ uVar11;
      uVar12 = uVar11 << 0x10 | uVar11 >> 0x10;
      uVar10 = local_c0 + uVar12;
      uVar8 = uVar10 ^ uVar5;
      uVar9 = uVar8 << 0xc | uVar8 >> 0x14;
      local_d4 = local_d4 + uVar5 + uVar9;
      uVar12 = uVar12 ^ local_d4;
      uVar3 = uVar3 ^ local_d0 + uVar6;
      local_a4 = uVar12 << 8 | uVar12 >> 0x18;
      uVar12 = uVar3 << 0x10 | uVar3 >> 0x10;
      uVar10 = local_a4 + uVar10;
      uVar8 = local_bc + uVar12;
      uVar9 = uVar10 ^ uVar9;
      uVar4 = uVar6 ^ uVar8;
      uVar9 = uVar9 << 7 | uVar9 >> 0x19;
      uVar5 = uVar4 << 0xc | uVar4 >> 0x14;
      local_d0 = local_d0 + uVar6 + uVar5;
      uVar2 = uVar7 + uVar2;
      uVar12 = local_d0 ^ uVar12;
      uVar12 = uVar12 << 8 | uVar12 >> 0x18;
      uVar8 = uVar12 + uVar8;
      uVar12 = uVar2 ^ uVar12;
      uVar5 = uVar8 ^ uVar5;
      uVar4 = uVar12 << 0x10 | uVar12 >> 0x10;
      uVar6 = uVar5 << 7 | uVar5 >> 0x19;
      uVar10 = uVar4 + uVar10;
      uVar7 = uVar7 ^ uVar10;
      uVar12 = uVar7 << 0xc | uVar7 >> 0x14;
      uVar2 = uVar12 + uVar2;
      uVar4 = uVar2 ^ uVar4;
      uVar3 = uVar4 << 8 | uVar4 >> 0x18;
      uVar10 = uVar3 + uVar10;
      uVar12 = uVar10 ^ uVar12;
      uVar4 = uVar12 << 7 | uVar12 >> 0x19;
      local_d8 = local_d8 + uVar9;
      uVar13 = uVar13 ^ local_d8;
      uVar12 = uVar13 << 0x10 | uVar13 >> 0x10;
      uVar8 = uVar8 + uVar12;
      uVar9 = uVar8 ^ uVar9;
      uVar5 = uVar9 << 0xc | uVar9 >> 0x14;
      local_d8 = uVar5 + local_d8;
      local_d4 = uVar6 + local_d4;
      uVar7 = local_b0 ^ local_d4;
      uVar12 = local_d8 ^ uVar12;
      uVar9 = uVar7 << 0x10 | uVar7 >> 0x10;
      uVar7 = uVar12 << 8 | uVar12 >> 0x18;
      uVar8 = uVar8 + uVar7;
      local_c4 = local_ac + uVar9;
      uVar5 = uVar5 ^ uVar8;
      uVar6 = local_c4 ^ uVar6;
      uVar5 = uVar5 << 7 | uVar5 >> 0x19;
      uVar6 = uVar6 << 0xc | uVar6 >> 0x14;
      local_d4 = uVar6 + local_d4;
      local_d0 = local_a8 + local_d0;
      uVar9 = local_d4 ^ uVar9;
      uVar9 = uVar9 << 8 | uVar9 >> 0x18;
      local_c4 = local_c4 + uVar9;
      uVar12 = local_d0 ^ local_a4;
      uVar6 = local_c4 ^ uVar6;
      uVar12 = uVar12 << 0x10 | uVar12 >> 0x10;
      uVar1 = uVar1 + uVar12;
      uVar6 = uVar6 << 7 | uVar6 >> 0x19;
      uVar11 = local_a8 ^ uVar1;
      uVar13 = uVar11 << 0xc | uVar11 >> 0x14;
      local_d0 = uVar13 + local_d0;
      uVar12 = local_d0 ^ uVar12;
      uVar11 = uVar12 << 8 | uVar12 >> 0x18;
      uVar1 = uVar1 + uVar11;
      uVar13 = uVar13 ^ uVar1;
      uVar12 = uVar13 << 7 | uVar13 >> 0x19;
      local_a0 = local_a0 - 1;
      local_cc = uVar3;
      local_c0 = uVar10;
      local_bc = uVar8;
      local_b8 = uVar4;
      local_b4 = uVar5;
    } while (local_a0 != 0);
  }
  local_c8 = uVar2 + *param_2;
  ((unsigned char*)&local_88)[3] = (undefined)((uint)local_c8 >> 0x18);
  param_1[3] = ((unsigned char*)&local_88)[3];
  ((unsigned char*)&local_88)[2] = (undefined)((uint)local_c8 >> 0x10);
  param_1[2] = ((unsigned char*)&local_88)[2];
  ((unsigned char*)&local_88)[1] = (undefined)((uint)local_c8 >> 8);
  param_1[1] = ((unsigned char*)&local_88)[1];
  *param_1 = (char)local_c8;
  local_d8 = local_d8 + param_2[1];
  ((unsigned char*)&uStack_84)[3] = (undefined)(local_d8 >> 0x18);
  param_1[7] = ((unsigned char*)&uStack_84)[3];
  ((unsigned char*)&uStack_84)[2] = (undefined)(local_d8 >> 0x10);
  param_1[6] = ((unsigned char*)&uStack_84)[2];
  ((unsigned char*)&uStack_84)[1] = (undefined)(local_d8 >> 8);
  param_1[5] = ((unsigned char*)&uStack_84)[1];
  param_1[4] = (char)local_d8;
  local_d4 = local_d4 + param_2[2];
  ((unsigned char*)&uStack_80)[3] = (undefined)(local_d4 >> 0x18);
  param_1[0xb] = ((unsigned char*)&uStack_80)[3];
  ((unsigned char*)&uStack_80)[2] = (undefined)(local_d4 >> 0x10);
  param_1[10] = ((unsigned char*)&uStack_80)[2];
  ((unsigned char*)&uStack_80)[1] = (undefined)(local_d4 >> 8);
  param_1[9] = ((unsigned char*)&uStack_80)[1];
  param_1[8] = (char)local_d4;
  local_d0 = local_d0 + param_2[3];
  ((unsigned char*)&uStack_7c)[3] = (undefined)(local_d0 >> 0x18);
  param_1[0xf] = ((unsigned char*)&uStack_7c)[3];
  ((unsigned char*)&uStack_7c)[2] = (undefined)(local_d0 >> 0x10);
  param_1[0xe] = ((unsigned char*)&uStack_7c)[2];
  ((unsigned char*)&uStack_7c)[1] = (undefined)(local_d0 >> 8);
  param_1[0xd] = ((unsigned char*)&uStack_7c)[1];
  param_1[0xc] = (char)local_d0;
  local_78 = uVar12 + param_2[4];
  ((unsigned char*)&local_78)[3] = (undefined)((uint)local_78 >> 0x18);
  param_1[0x13] = ((unsigned char*)&local_78)[3];
  ((unsigned char*)&local_78)[2] = (undefined)((uint)local_78 >> 0x10);
  param_1[0x12] = ((unsigned char*)&local_78)[2];
  ((unsigned char*)&local_78)[1] = (undefined)((uint)local_78 >> 8);
  param_1[0x11] = ((unsigned char*)&local_78)[1];
  param_1[0x10] = (char)local_78;
  uStack_74 = uVar4 + param_2[5];
  ((unsigned char*)&uStack_74)[3] = (undefined)((uint)uStack_74 >> 0x18);
  param_1[0x17] = ((unsigned char*)&uStack_74)[3];
  ((unsigned char*)&uStack_74)[2] = (undefined)((uint)uStack_74 >> 0x10);
  param_1[0x16] = ((unsigned char*)&uStack_74)[2];
  ((unsigned char*)&uStack_74)[1] = (undefined)((uint)uStack_74 >> 8);
  param_1[0x15] = ((unsigned char*)&uStack_74)[1];
  param_1[0x14] = (char)uStack_74;
  uStack_70 = uVar5 + param_2[6];
  ((unsigned char*)&uStack_70)[3] = (undefined)((uint)uStack_70 >> 0x18);
  param_1[0x1b] = ((unsigned char*)&uStack_70)[3];
  ((unsigned char*)&uStack_70)[2] = (undefined)((uint)uStack_70 >> 0x10);
  param_1[0x1a] = ((unsigned char*)&uStack_70)[2];
  ((unsigned char*)&uStack_70)[1] = (undefined)((uint)uStack_70 >> 8);
  param_1[0x19] = ((unsigned char*)&uStack_70)[1];
  param_1[0x18] = (char)uStack_70;
  uStack_6c = uVar6 + param_2[7];
  ((unsigned char*)&uStack_6c)[3] = (undefined)((uint)uStack_6c >> 0x18);
  param_1[0x1f] = ((unsigned char*)&uStack_6c)[3];
  ((unsigned char*)&uStack_6c)[2] = (undefined)((uint)uStack_6c >> 0x10);
  param_1[0x1e] = ((unsigned char*)&uStack_6c)[2];
  ((unsigned char*)&uStack_6c)[1] = (undefined)((uint)uStack_6c >> 8);
  param_1[0x1d] = ((unsigned char*)&uStack_6c)[1];
  param_1[0x1c] = (char)uStack_6c;
  local_68 = local_c4 + param_2[8];
  ((unsigned char*)&local_68)[3] = (undefined)((uint)local_68 >> 0x18);
  param_1[0x23] = ((unsigned char*)&local_68)[3];
  ((unsigned char*)&local_68)[2] = (undefined)((uint)local_68 >> 0x10);
  param_1[0x22] = ((unsigned char*)&local_68)[2];
  ((unsigned char*)&local_68)[1] = (undefined)((uint)local_68 >> 8);
  param_1[0x21] = ((unsigned char*)&local_68)[1];
  param_1[0x20] = (char)local_68;
  uStack_64 = uVar1 + param_2[9];
  ((unsigned char*)&uStack_64)[3] = (undefined)((uint)uStack_64 >> 0x18);
  param_1[0x27] = ((unsigned char*)&uStack_64)[3];
  ((unsigned char*)&uStack_64)[2] = (undefined)((uint)uStack_64 >> 0x10);
  param_1[0x26] = ((unsigned char*)&uStack_64)[2];
  ((unsigned char*)&uStack_64)[1] = (undefined)((uint)uStack_64 >> 8);
  param_1[0x25] = ((unsigned char*)&uStack_64)[1];
  param_1[0x24] = (char)uStack_64;
  uStack_60 = uVar10 + param_2[10];
  ((unsigned char*)&uStack_60)[3] = (undefined)((uint)uStack_60 >> 0x18);
  param_1[0x2b] = ((unsigned char*)&uStack_60)[3];
  ((unsigned char*)&uStack_60)[2] = (undefined)((uint)uStack_60 >> 0x10);
  param_1[0x2a] = ((unsigned char*)&uStack_60)[2];
  ((unsigned char*)&uStack_60)[1] = (undefined)((uint)uStack_60 >> 8);
  param_1[0x29] = ((unsigned char*)&uStack_60)[1];
  param_1[0x28] = (char)uStack_60;
  uStack_5c = uVar8 + param_2[0xb];
  ((unsigned char*)&uStack_5c)[3] = (undefined)((uint)uStack_5c >> 0x18);
  param_1[0x2f] = ((unsigned char*)&uStack_5c)[3];
  ((unsigned char*)&uStack_5c)[2] = (undefined)((uint)uStack_5c >> 0x10);
  param_1[0x2e] = ((unsigned char*)&uStack_5c)[2];
  ((unsigned char*)&uStack_5c)[1] = (undefined)((uint)uStack_5c >> 8);
  param_1[0x2d] = ((unsigned char*)&uStack_5c)[1];
  param_1[0x2c] = (char)uStack_5c;
  local_58 = uVar7 + param_2[0xc];
  ((unsigned char*)&local_58)[3] = (undefined)((uint)local_58 >> 0x18);
  param_1[0x33] = ((unsigned char*)&local_58)[3];
  ((unsigned char*)&local_58)[2] = (undefined)((uint)local_58 >> 0x10);
  param_1[0x32] = ((unsigned char*)&local_58)[2];
  ((unsigned char*)&local_58)[1] = (undefined)((uint)local_58 >> 8);
  param_1[0x31] = ((unsigned char*)&local_58)[1];
  param_1[0x30] = (char)local_58;
  uStack_54 = uVar9 + param_2[0xd];
  ((unsigned char*)&uStack_54)[3] = (undefined)((uint)uStack_54 >> 0x18);
  param_1[0x37] = ((unsigned char*)&uStack_54)[3];
  ((unsigned char*)&uStack_54)[2] = (undefined)((uint)uStack_54 >> 0x10);
  param_1[0x36] = ((unsigned char*)&uStack_54)[2];
  ((unsigned char*)&uStack_54)[1] = (undefined)((uint)uStack_54 >> 8);
  param_1[0x35] = ((unsigned char*)&uStack_54)[1];
  param_1[0x34] = (char)uStack_54;
  uStack_50 = uVar11 + param_2[0xe];
  ((unsigned char*)&uStack_50)[3] = (undefined)((uint)uStack_50 >> 0x18);
  param_1[0x3b] = ((unsigned char*)&uStack_50)[3];
  ((unsigned char*)&uStack_50)[2] = (undefined)((uint)uStack_50 >> 0x10);
  param_1[0x3a] = ((unsigned char*)&uStack_50)[2];
  ((unsigned char*)&uStack_50)[1] = (undefined)((uint)uStack_50 >> 8);
  param_1[0x39] = ((unsigned char*)&uStack_50)[1];
  param_1[0x38] = (char)uStack_50;
  uStack_4c = uVar3 + param_2[0xf];
  ((unsigned char*)&uStack_4c)[3] = (undefined)((uint)uStack_4c >> 0x18);
  param_1[0x3f] = ((unsigned char*)&uStack_4c)[3];
  ((unsigned char*)&uStack_4c)[2] = (undefined)((uint)uStack_4c >> 0x10);
  param_1[0x3e] = ((unsigned char*)&uStack_4c)[2];
  ((unsigned char*)&uStack_4c)[1] = (undefined)((uint)uStack_4c >> 8);
  param_1[0x3d] = ((unsigned char*)&uStack_4c)[1];
  param_1[0x3c] = (char)uStack_4c;
  local_98 = param_1;
  local_90 = param_2;
  local_88 = local_c8;
  uStack_84 = local_d8;
  uStack_80 = local_d4;
  uStack_7c = local_d0;
  FUN_140002530(local_48 ^ (ulonglong)&local_d8);
  return;
}



int FUN_140001b90(uint *param_1,uint *param_2,uint param_3,uint *param_4)

{
  uint uVar1;
  uint uVar2;
  uint uVar3;
  uint uVar4;
  uint uVar5;
  uint uVar6;
  uint uVar7;
  uint uVar8;
  uint uVar9;
  uint uVar10;
  uint uVar11;
  uint uVar12;
  uint *puVar13;
  ulonglong uVar14;
  byte *pbVar15;
  uint uVar16;
  uint *puVar17;
  ulonglong uVar18;
  longlong lVar19;
  ulonglong uVar20;
  undefined auStack_98 [32];
  uint local_78 [7];
  uint uStack_5c;
  uint local_58;
  uint uStack_54;
  uint uStack_50;
  uint uStack_4c;
  uint local_48;
  uint uStack_44;
  uint uStack_40;
  undefined auStack_3c [4];
  ulonglong local_38;
  
  local_38 = DAT_140006008 ^ (ulonglong)auStack_98;
  uVar18 = (ulonglong)param_3;
  if (param_3 == 0) goto LAB_140001e6f;
  uVar11 = param_1[0x20];
  uVar20 = uVar18;
  if (uVar11 != 0) {
    if (uVar11 < param_3) {
      uVar18 = (ulonglong)uVar11;
LAB_140001be6:
      uVar12 = (uint)uVar18;
      puVar17 = param_4;
      uVar20 = uVar18;
      do {
        *(byte *)puVar17 =
             *(byte *)((ulonglong)(0x40 - uVar11) + 0x40 + (longlong)param_1) ^
             *(byte *)((longlong)param_2 + (-1 - (longlong)param_4) +
                      (longlong)(uint *)((longlong)puVar17 + 1));
        param_1[0x20] = param_1[0x20] - 1;
        uVar11 = param_1[0x20];
        uVar20 = uVar20 - 1;
        puVar17 = (uint *)((longlong)puVar17 + 1);
      } while (uVar20 != 0); // state -> param_2 copy routine (first 64 - 8 byte)
    }
    else {
      uVar12 = param_3;
      if (param_3 != 0) goto LAB_140001be6;
    }
    uVar20 = (ulonglong)(param_3 - uVar12);
    if (param_3 - uVar12 == 0) goto LAB_140001e6f;
    param_4 = (uint *)((longlong)param_4 + uVar18);
    param_2 = (uint *)((longlong)param_2 + uVar18);
  }
  puVar17 = (uint *)((longlong)param_4 + 0x3f);
LAB_140001c40:
  FUN_140001670((undefined *)local_78,param_1,param_1[0x22]);
  uVar11 = param_1[0xc] + 1;
  param_1[0xc] = uVar11;
  if (param_1[0x21] == 8) {
    if (uVar11 == 0) {
      puVar13 = param_1 + 0xd;
      *puVar13 = *puVar13 + 1;
      uVar11 = *puVar13;
      goto LAB_140001c71;
    }
  }
  else {
LAB_140001c71:
    if (uVar11 == 0) goto LAB_140001e6f;
  }
  uVar11 = (uint)uVar20;
  if (0x40 < uVar11) {
    if (((auStack_3c + 3 < (void*)param_4) || (puVar17 < local_78)) &&
       (((uint *)((longlong)param_2 + 0x3fU) < param_4 || (puVar17 < param_2)))) {
      uVar12 = param_2[1];
      uVar1 = param_2[2];
      uVar2 = param_2[3];
      uVar3 = param_2[4];
      uVar4 = param_2[5];
      uVar5 = param_2[6];
      uVar6 = param_2[7];
      *param_4 = *param_2 ^ local_78[0];
      param_4[1] = uVar12 ^ local_78[1];
      param_4[2] = uVar1 ^ local_78[2];
      param_4[3] = uVar2 ^ local_78[3];
      uVar12 = param_2[8];
      uVar1 = param_2[9];
      uVar2 = param_2[10];
      uVar7 = param_2[0xb];
      *(uint *)((longlong)puVar17 + -0x2f) = uVar3 ^ local_78[4];
      *(uint *)((longlong)puVar17 + -0x2b) = uVar4 ^ local_78[5];
      *(uint *)((longlong)puVar17 + -0x27) = uVar5 ^ local_78[6];
      *(uint *)((longlong)puVar17 + -0x23) = uVar6 ^ uStack_5c;
      uVar3 = param_2[0xc];
      uVar4 = param_2[0xd];
      uVar5 = param_2[0xe];
      uVar6 = param_2[0xf];
      *(uint *)((longlong)puVar17 + -0x1f) = uVar12 ^ local_58;
      *(uint *)((longlong)puVar17 + -0x1b) = uVar1 ^ uStack_54;
      *(uint *)((longlong)puVar17 + -0x17) = uVar2 ^ uStack_50;
      *(uint *)((longlong)puVar17 + -0x13) = uVar7 ^ uStack_4c;
      *(uint *)((longlong)puVar17 + -0xf) = uVar3 ^ local_48;
      *(uint *)((longlong)puVar17 + -0xb) = uVar4 ^ uStack_44;
      *(uint *)((longlong)puVar17 + -7) = uVar5 ^ uStack_40;
      //*(uint *)((longlong)puVar17 + -3) = uVar6 ^ (uint)auStack_3c;
      *(uint *)((longlong)puVar17 + -3) = uVar6 ^ *(uint*)&auStack_3c;
      uVar20 = (ulonglong)(uVar11 - 0x40);
      param_4 = param_4 + 0x10;
      puVar17 = puVar17 + 0x10;
      param_2 = param_2 + 0x10;
    }
    else {
      puVar13 = local_78;
      lVar19 = 0x40;
      do {
        *(byte *)(((longlong)puVar17 - (longlong)(auStack_3c + 3)) + (longlong)puVar13) =
             ((byte *)((longlong)puVar13 + (0x10 - (longlong)(local_78 + 4))))[(longlong)param_2] ^
             *(byte *)puVar13;
        puVar13 = (uint *)((longlong)puVar13 + 1);
        lVar19 = lVar19 + -1;
      } while (lVar19 != 0);
      uVar20 = (ulonglong)(uVar11 - 0x40);
      param_4 = param_4 + 0x10;
      puVar17 = puVar17 + 0x10;
      param_2 = param_2 + 0x10;
    }
    goto LAB_140001c40;
  }
  uVar18 = 0;
  if (uVar11 != 0) {
    if (0x3f < uVar11) {
      uVar12 = uVar11 - 1;
      if ((((uint *)((longlong)local_78 + (ulonglong)uVar12) < param_4) ||
          ((uint *)((ulonglong)uVar12 + (longlong)param_4) < local_78)) &&
         (((uint *)((ulonglong)uVar12 + (longlong)param_2) < param_4 ||
          ((uint *)((ulonglong)uVar12 + (longlong)param_4) < param_2)))) {
        uVar12 = 0x20;
        do {
          uVar1 = *(uint *)((longlong)local_78 + uVar18 + 4);
          uVar2 = *(uint *)((longlong)local_78 + uVar18 + 8);
          uVar3 = *(uint *)((longlong)local_78 + uVar18 + 0xc);
          uVar14 = (ulonglong)(uVar12 - 0x10);
          puVar17 = (uint *)(uVar18 + (longlong)param_2);
          uVar4 = puVar17[1];
          uVar5 = puVar17[2];
          uVar6 = puVar17[3];
          uVar7 = *(uint *)((longlong)local_78 + uVar14);
          uVar8 = *(uint *)((longlong)local_78 + uVar14 + 4);
          uVar9 = *(uint *)((longlong)local_78 + uVar14 + 8);
          uVar10 = *(uint *)((longlong)local_78 + uVar14 + 0xc);
          puVar13 = (uint *)(uVar18 + (longlong)param_4);
          *puVar13 = *puVar17 ^ *(uint *)((longlong)local_78 + uVar18);
          puVar13[1] = uVar4 ^ uVar1;
          puVar13[2] = uVar5 ^ uVar2;
          puVar13[3] = uVar6 ^ uVar3;
          uVar16 = (int)uVar18 + 0x40;
          uVar18 = (ulonglong)uVar16;
          puVar17 = (uint *)(uVar14 + (longlong)param_2);
          uVar1 = puVar17[1];
          uVar2 = puVar17[2];
          uVar3 = puVar17[3];
          puVar13 = (uint *)(uVar14 + (longlong)param_4);
          *puVar13 = *puVar17 ^ uVar7;
          puVar13[1] = uVar1 ^ uVar8;
          puVar13[2] = uVar2 ^ uVar9;
          puVar13[3] = uVar3 ^ uVar10;
          uVar14 = (ulonglong)uVar12;
          uVar1 = *(uint *)((longlong)local_78 + uVar14 + 4);
          uVar2 = *(uint *)((longlong)local_78 + uVar14 + 8);
          uVar3 = *(uint *)((longlong)local_78 + uVar14 + 0xc);
          puVar17 = (uint *)(uVar14 + (longlong)param_2);
          uVar4 = puVar17[1];
          uVar5 = puVar17[2];
          uVar6 = puVar17[3];
          puVar13 = (uint *)(uVar14 + (longlong)param_4);
          *puVar13 = *puVar17 ^ *(uint *)((longlong)local_78 + uVar14);
          puVar13[1] = uVar4 ^ uVar1;
          puVar13[2] = uVar5 ^ uVar2;
          puVar13[3] = uVar6 ^ uVar3;
          uVar14 = (ulonglong)(uVar12 + 0x10);
          uVar12 = uVar12 + 0x40;
          puVar17 = (uint *)(uVar14 + (longlong)param_2);
          uVar1 = puVar17[1];
          uVar2 = puVar17[2];
          uVar3 = puVar17[3];
          uVar4 = *(uint *)((longlong)local_78 + uVar14 + 4);
          uVar5 = *(uint *)((longlong)local_78 + uVar14 + 8);
          uVar6 = *(uint *)((longlong)local_78 + uVar14 + 0xc);
          puVar13 = (uint *)(uVar14 + (longlong)param_4);
          *puVar13 = *puVar17 ^ *(uint *)((longlong)local_78 + uVar14);
          puVar13[1] = uVar1 ^ uVar4;
          puVar13[2] = uVar2 ^ uVar5;
          puVar13[3] = uVar3 ^ uVar6;
        } while (uVar16 < (uVar11 & 0xffffffc0));
        if (uVar11 <= uVar16) goto LAB_140001e43;
      }
    }
    pbVar15 = (byte *)((longlong)local_78 + uVar18);
    uVar18 = (ulonglong)(uVar11 - (int)uVar18);
    do {
      pbVar15[(longlong)param_4 - (longlong)local_78] =
           pbVar15[(longlong)param_2 - (longlong)local_78] ^ *pbVar15;
      pbVar15 = pbVar15 + 1;
      uVar18 = uVar18 - 1;
    } while (uVar18 != 0); // last 8 byte copying
  }
LAB_140001e43:
  param_1[0x20] = 0x40 - uVar11;
  if (uVar11 < 0x40) {
    memcpy((void *)((longlong)param_1 + uVar20 + 0x40),(void *)((longlong)local_78 + uVar20),
           (ulonglong)(0x40 - uVar11));
  }
LAB_140001e6f:
  FUN_140002530(local_38 ^ (ulonglong)auStack_98);
  return 1; // TODO assume always success
}



undefined8 FUN_140001ea0(undefined4 *param_1,undefined4 *param_2)

{
  *param_1 = 0x61707865;
  param_1[1] = 0x3320646e;
  param_1[2] = 0x79622d32;
  param_1[3] = 0x6b206574;

  param_1[4] = *param_2;
  param_1[5] = param_2[1];
  param_1[6] = param_2[2];
  param_1[7] = param_2[3];
  param_1[8] = param_2[4];
  param_1[9] = param_2[5];
  param_1[10] = param_2[6];
  param_1[0xb] = param_2[7];

  param_1[0x22] = 0x14;
  param_1[0x21] = 0;
  return 0;
}



// param_1 random 0x28 bytes
// param_2 0x28
// param_3 chacha ctx
void FUN_1400020f0(byte *param_1,uint param_2,uint *param_3)

{
  byte *pbVar1;
  int iVar2;
  undefined8 uVar3;
  undefined *puVar4;
  longlong lVar5;
  ulonglong uVar6;
  ulonglong uVar7;
  ulonglong uVar8;
  undefined auStack_58 [32];
  undefined local_38 [16];
  undefined local_28 [16];
  undefined8 local_18;
  ulonglong local_10;
  
  local_10 = DAT_140006008 ^ (ulonglong)auStack_58;
  if (*(short *)(param_3 + 0x2e) == 0) {
    if (param_2 != 0) {
      do {
        pbVar1 = (byte *)((ulonglong)param_3[0x2d] % 0x28 + 0x8c + (longlong)param_3);
        *pbVar1 = *pbVar1 ^ *param_1;
        param_3[0x2d] = param_3[0x2d] + 1;
        param_2 = param_2 - 1;
        param_1 = param_1 + 1;
      } while (param_2 != 0);
    }
  }
  else {
    lVar5 = 0x28;
    local_18 = 0;
    //local_38 = ZEXT816(0);
    zero16(&local_38);
    //local_28 = ZEXT816(0);
    zero16(&local_28);
    iVar2 = FUN_140001b90(param_3,(uint *)local_38,0x28,(uint *)local_38);
    if (iVar2 == 0) {
      uVar8 = 0;
      if (param_2 != 0) {
        uVar7 = (ulonglong)param_2;
        uVar6 = uVar8;
        do {
          local_38[uVar6 % 0x28] = local_38[uVar6 % 0x28] ^ *param_1;
          uVar7 = uVar7 - 1;
          param_1 = param_1 + 1;
          uVar6 = uVar6 + 1;
        } while (uVar7 != 0);
      }
      uVar3 = FUN_140001ea0(param_3,(undefined4 *)local_38);
      if ((int)uVar3 == 0) {
        *(ulonglong *)(param_3 + 0xc) = uVar8;
        param_3[0x20] = (uint)uVar8;
        param_3[0x21] = 8;
        param_3[0xe] = (uint)local_18;
        puVar4 = local_38;
        param_3[0xf] = (uint)((ulonglong)local_18 >> 0x20);
        do {
          *puVar4 = (char)uVar8;
          puVar4 = puVar4 + 1;
          lVar5 = lVar5 + -1;
        } while (lVar5 != 0);
      }
    }
  }
  FUN_140002530(local_10 ^ (ulonglong)auStack_58);
  return;
}



undefined8 FUN_1400022b0(undefined4 *param_1)

{
  undefined8 uVar1;
  
  if (*(short *)(param_1 + 0x2e) == 0) {
    uVar1 = FUN_140001ea0(param_1,param_1 + 0x23);
    if ((int)uVar1 == 0) {
      *(undefined8 *)(param_1 + 0xc) = 0;
      param_1[0xe] = param_1[0x2b];
      param_1[0x20] = 0;
      param_1[0x21] = 8;
      param_1[0xf] = param_1[0x2c];
      //*(undefined (*) [16])(param_1 + 0x23) = ZEXT816(0);
      zero16((undefined (*) [16])(param_1 + 0x23));
      //*(undefined (*) [16])(param_1 + 0x27) = ZEXT816(0);
      zero16((undefined (*) [16])(param_1 + 0x27));
      *(undefined8 *)(param_1 + 0x2b) = 0;
      *(undefined2 *)(param_1 + 0x2e) = 1;
      param_1[0x2d] = 0;
    }
  }
  return 0;
}

void FUN_140002530(longlong param_1)

{
  if ((param_1 == DAT_140006008) && ((short)((ulonglong)param_1 >> 0x30) == 0)) {
    return;
  }
  FUN_1400027f8();
  return;
}






int main()
{
  FUN_1400012f0();
  return 0;
}



// Library Function - Single Match
//  __raise_securityfailure
// 
// Libraries: Visual Studio 2015 Release, Visual Studio 2017 Release, Visual Studio 2019 Release

void __raise_securityfailure(_EXCEPTION_POINTERS *param_1)

{
  fprintf(stderr, "[%s:%d:%s] not implemented", __FILE__, __LINE__, __FUNCTION__);
//  HANDLE pvVar1;
//  
//  SetUnhandledExceptionFilter((LPTOP_LEVEL_EXCEPTION_FILTER)0x0);
//  UnhandledExceptionFilter(param_1);
//  pvVar1 = GetCurrentProcess();
//                    // WARNING: Could not recover jumptable at 0x0001400027f1. Too many branches
//                    // WARNING: Treating indirect jump as call
//  TerminateProcess(pvVar1,0xc0000409);
//  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_1400027f8(void)

{
  fprintf(stderr, "[%s:%d:%s] not implemented", __FILE__, __LINE__, __FUNCTION__);
//  code *pcVar1;
//  BOOL BVar2;
//  undefined *puVar3;
//  undefined auStack_38 [8];
//  undefined auStack_30 [48];
//  
//  puVar3 = auStack_38;
//  BVar2 = IsProcessorFeaturePresent(0x17);
//  if (BVar2 != 0) {
//    pcVar1 = (code *)swi(0x29);
//    (*pcVar1)(2);
//    puVar3 = auStack_30;
//  }
//  *(undefined8 *)(puVar3 + -8) = 0x140002823;
//  capture_previous_context((PCONTEXT)&DAT_1400060e0);
//  _DAT_140006050 = *(undefined8 *)(puVar3 + 0x38);
//  _DAT_140006178 = puVar3 + 0x40;
//  _DAT_140006160 = *(undefined8 *)(puVar3 + 0x40);
//  _DAT_140006040 = 0xc0000409;
//  _DAT_140006044 = 1;
//  _DAT_140006058 = 1;
//  DAT_140006060 = 2;
//  *(undefined8 *)(puVar3 + 0x20) = DAT_140006008;
//  *(undefined8 *)(puVar3 + 0x28) = DAT_140006000;
//  *(undefined8 *)(puVar3 + -8) = 0x1400028c5;
//  DAT_1400061d8 = _DAT_140006050;
//  __raise_securityfailure((_EXCEPTION_POINTERS *)&PTR_DAT_1400042b0);
//  return;
}


