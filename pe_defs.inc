%ifndef __PE_DEFS
%define __PE_DEFS

;******************************************************
; IMAGE_FILE_HEADER constants
;******************************************************
IMAGE_DOS_SIGNATURE         equ     0x5A4D
IMAGE_OS2_SIGNATURE         equ     0x454E
IMAGE_OS2_SIGNATURE_LE      equ     0x454C
IMAGE_VXD_SIGNATURE         equ     0x454C
;-------------------------------------------------------------------

; IMAGE_NT_HEADERS consts
IMAGE_NT_SIGNATURE          equ     0x00004550

;******************************************************
; IMAGE_FILE_HEADER constants
;******************************************************
; IMAGE_FILE_HEADER machine types
IMAGE_FILE_MACHINE_UNKNOWN      equ     0x0
IMAGE_FILE_MACHINE_AM33	        equ     0x1d3
IMAGE_FILE_MACHINE_AMD64        equ     0x8664
IMAGE_FILE_MACHINE_ARM          equ     0x1c0
IMAGE_FILE_MACHINE_ARMNT        equ     0x1c4
IMAGE_FILE_MACHINE_EBC	        equ     0xebc
IMAGE_FILE_MACHINE_I386	        equ     0x14c
IMAGE_FILE_MACHINE_IA64	        equ     0x200
IMAGE_FILE_MACHINE_M32R	        equ     0x9041
IMAGE_FILE_MACHINE_MIPS16       equ     0x266
IMAGE_FILE_MACHINE_MIPSFPU	    equ     0x366
IMAGE_FILE_MACHINE_MIPSFPU16    equ     0x466
IMAGE_FILE_MACHINE_POWERPC      equ     0x1f0
IMAGE_FILE_MACHINE_POWERPCFP    equ     0x1f1
IMAGE_FILE_MACHINE_R4000        equ     0x166
IMAGE_FILE_MACHINE_RISCV32	    equ     0x5032
IMAGE_FILE_MACHINE_RISCV64      equ     0x5064
IMAGE_FILE_MACHINE_RISCV128	    equ     0x5128
IMAGE_FILE_MACHINE_SH3          equ     0x1a2
IMAGE_FILE_MACHINE_SH3DSP       equ     0x1a3
IMAGE_FILE_MACHINE_SH4          equ     0x1a6
IMAGE_FILE_MACHINE_SH5          equ     0x1a8
IMAGE_FILE_MACHINE_THUMB        equ     0x1c2
IMAGE_FILE_MACHINE_WCEMIPSV2    equ     0x169

; IMAGE_FILE_HEADER characteristics
IMAGE_FILE_RELOCS_STRIPPED              equ     0x0001
IMAGE_FILE_EXECUTABLE_IMAGE	            equ     0x0002
IMAGE_FILE_LINE_NUMS_STRIPPED           equ     0x0004
IMAGE_FILE_LOCAL_SYMS_STRIPPED          equ     0x0008
IMAGE_FILE_AGGRESSIVE_WS_TRIM           equ     0x0010
IMAGE_FILE_LARGE_ADDRESS_AWARE          equ     0x0020
IMAGE_FILE_RESV_VALUE                   equ     0x0040
IMAGE_FILE_BYTES_REVERSED_LO            equ     0x0080
IMAGE_FILE_32BIT_MACHINE                equ     0x0100
IMAGE_FILE_DEBUG_STRIPPED               equ     0x0200
IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP      equ     0x0400
IMAGE_FILE_NET_RUN_FROM_SWAP            equ     0x0800
IMAGE_FILE_SYSTEM                       equ     0x1000
IMAGE_FILE_DLL                          equ     0x2000
IMAGE_FILE_UP_SYSTEM_ONLY               equ     0x4000
IMAGE_FILE_BYTES_REVERSED_HI            equ     0x8000
;-------------------------------------------------------------------

;******************************************************
; IMAGE_OPTIONAL_HEADER constants
;******************************************************
IMAGE_NUMBEROF_DIRECTORY_ENTRIES    equ     16

; IMAGE_OPTIONAL_HEADER magic
IMAGE_NT_OPTIONAL_HDR32_MAGIC       equ     0x10b
IMAGE_NT_OPTIONAL_HDR64_MAGIC       equ     0x20b
IMAGE_ROM_OPTIONAL_HDR_MAGIC        equ     0x107

; IMAGE_OPTIONAL_HEADER subsystem
IMAGE_SUBSYSTEM_UNKNOWN                     equ     0
IMAGE_SUBSYSTEM_NATIVE                      equ     1
IMAGE_SUBSYSTEM_WINDOWS_GUI	                equ     2
IMAGE_SUBSYSTEM_WINDOWS_CUI                 equ     3
IMAGE_SUBSYSTEM_POSIX_CUI                   equ     7
IMAGE_SUBSYSTEM_WINDOWS_CE_GUI              equ     9
IMAGE_SUBSYSTEM_EFI_APPLICATION	            equ     10
IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER     equ     11
IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER          equ     12
IMAGE_SUBSYSTEM_EFI_ROM	                    equ     13
IMAGE_SUBSYSTEM_XBOX                        equ     14
IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION    equ     16

; IMAGE_OPTIONAL_HEADER dll characteristics
IMAGE_DLLCHARACTERISTICS_RESV1	                    equ     0x0001
IMAGE_DLLCHARACTERISTICS_RESV2	                    equ     0x0002
IMAGE_DLLCHARACTERISTICS_RESV3	                    equ     0x0004
IMAGE_DLLCHARACTERISTICS_RESV4                      equ     0x0008
IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA            equ     0x0020
IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE               equ     0x0040
IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY            equ     0x0080
IMAGE_DLLCHARACTERISTICS_NX_COMPAT                  equ     0x0100
IMAGE_DLLCHARACTERISTICS_NO_ISOLATION               equ     0x0200
IMAGE_DLLCHARACTERISTICS_NO_SEH	                    equ     0x0400
IMAGE_DLLCHARACTERISTICS_NO_BIND                    equ     0x0800
IMAGE_DLLCHARACTERISTICS_APPCONTAINER               equ     0x1000
IMAGE_DLLCHARACTERISTICS_WDM_DRIVER	                equ     0x2000
IMAGE_DLLCHARACTERISTICS_GUARD_CF                   equ     0x4000
IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE      equ     0x8000

; Data directories constants
IMAGE_DIRECTORY_ENTRY_EXPORT                equ     0
IMAGE_DIRECTORY_ENTRY_IMPORT                equ     1
IMAGE_DIRECTORY_ENTRY_RESOURCE              equ     2
IMAGE_DIRECTORY_ENTRY_EXCEPTION             equ     3
IMAGE_DIRECTORY_ENTRY_SECURITY              equ     4
IMAGE_DIRECTORY_ENTRY_BASERELOC             equ     5
IMAGE_DIRECTORY_ENTRY_DEBUG                 equ     6
IMAGE_DIRECTORY_ENTRY_ARCHITECTURE          equ     7
IMAGE_DIRECTORY_ENTRY_GLOBALPTR             equ     8
IMAGE_DIRECTORY_ENTRY_TLS                   equ     9
IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG           equ     10
IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT          equ     11
IMAGE_DIRECTORY_ENTRY_IAT                   equ     12
IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT          equ     13
IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR        equ     14
;-------------------------------------------------------------------

;******************************************************
; IMAGE_SECTION_HEADER constants
;******************************************************
; IMAGE_SECTION_HEADER Characteristics
IMAGE_SCN_RESV1                     equ     0x00000000
IMAGE_SCN_RESV2                     equ     0x00000001
IMAGE_SCN_RESV3                     equ     0x00000002
IMAGE_SCN_RESV4                     equ     0x00000004
IMAGE_SCN_TYPE_NO_PAD               equ     0x00000008
IMAGE_SCN_RESV5                     equ     0x00000010
IMAGE_SCN_CNT_CODE                  equ     0x00000020
IMAGE_SCN_CNT_INITIALIZED_DATA      equ     0x00000040
IMAGE_SCN_CNT_UNINITIALIZED_DATA    equ     0x00000080
IMAGE_SCN_LNK_OTHER	                equ     0x00000100
IMAGE_SCN_LNK_INFO                  equ     0x00000200
IMAGE_SCN_RESV6	                    equ     0x00000400
IMAGE_SCN_LNK_REMOVE                equ     0x00000800
IMAGE_SCN_LNK_COMDAT                equ     0x00001000
IMAGE_SCN_GPREL	                    equ     0x00008000
IMAGE_SCN_MEM_PURGEABLE	            equ     0x00020000
IMAGE_SCN_MEM_16BIT	                equ     0x00020000
IMAGE_SCN_MEM_LOCKED                equ     0x00040000
IMAGE_SCN_MEM_PRELOAD               equ     0x00080000
IMAGE_SCN_ALIGN_1BYTES	            equ     0x00100000
IMAGE_SCN_ALIGN_2BYTES              equ     0x00200000
IMAGE_SCN_ALIGN_4BYTES              equ     0x00300000
IMAGE_SCN_ALIGN_8BYTES              equ     0x00400000
IMAGE_SCN_ALIGN_16BYTES	            equ     0x00500000
IMAGE_SCN_ALIGN_32BYTES	            equ     0x00600000
IMAGE_SCN_ALIGN_64BYTES	            equ     0x00700000
IMAGE_SCN_ALIGN_128BYTES            equ     0x00800000
IMAGE_SCN_ALIGN_256BYTES            equ     0x00900000
IMAGE_SCN_ALIGN_512BYTES            equ     0x00A00000
IMAGE_SCN_ALIGN_1024BYTES           equ     0x00B00000
IMAGE_SCN_ALIGN_2048BYTES           equ     0x00C00000
IMAGE_SCN_ALIGN_4096BYTES           equ     0x00D00000
IMAGE_SCN_ALIGN_8192BYTES           equ     0x00E00000
IMAGE_SCN_LNK_NRELOC_OVFL           equ     0x01000000
IMAGE_SCN_MEM_DISCARDABLE           equ     0x02000000
IMAGE_SCN_MEM_NOT_CACHED            equ     0x04000000
IMAGE_SCN_MEM_NOT_PAGED             equ     0x08000000
IMAGE_SCN_MEM_SHARED                equ     0x10000000
IMAGE_SCN_MEM_EXECUTE               equ     0x20000000
IMAGE_SCN_MEM_READ                  equ     0x40000000
IMAGE_SCN_MEM_WRITE                 equ     0x80000000
;-------------------------------------------------------------------

; IMAGE_DOS_HEADER
struc DosHeader
    .e_magic        resw    1
    .e_cblp         resw    1
    .e_cp           resw    1
    .e_crlc	        resw    1
    .e_cparhdr      resw    1
    .e_minalloc     resw    1
    .e_maxalloc     resw    1
    .e_ss           resw    1
    .e_sp	        resw    1
    .e_csum	        resw    1
    .e_ip	        resw    1
    .e_cs	        resw    1
    .e_lfarlc   	resw    1
    .e_ovno     	resw    1
    .e_res	        resw    4
    .e_oemid	    resw    1
    .e_oeminfo	    resw    1
    .e_res2	        resw    10
    .e_lfanew       resd    1
endstruc

; IMAGE_FILE_HEADER
struc FileHeader
    .Machine                resw    1
    .NumberOfSections       resw    1
    .TimeDateStamp          resd    1
    .PointerToSymbolTable   resd    1
    .NumberOfSymbols        resd    1
    .SizeOfOptionalHeader   resw    1
    .Characteristics        resw    1
endstruc

; IMAGE_DATA_DIRECTORY
struc DataDirectoryEntry
    .VirtualAddress     resd    1 ; Actually RVA from image base address
    .Size               resd    1 ; Size in bytes
endstruc

; IMAGE_OPTIONAL_HEADER32
struc OptionalHeader32
    ; Same sizes for both PE32 and PE32+
    .Magic                      resw    1
    .MajorLinkerVersion         resb    1
    .MinorLinkerVersion         resb    1
    .SizeOfCode                 resd    1
    .SizeOfInitializedData      resd    1
    .SizeOfUninitializedData    resd    1
    .AddressOfEntryPoint        resd    1 ; Actually RVA from the image base
    .BaseOfCode                 resd    1 ; Actually RVA from the image base

    ; Only in PE32
    .BaseOfData     resd    1; Actually RVA from the image base

    ; Windows specific fields, sizes are only for PE32
    .ImageBase                      resd    1
    .SectionAlignment               resd    1
    .FileAlignment                  resd    1
    .MajorOperatingSystemVersion    resw    1
    .MinorOperatingSystemVersion    resw    1
    .MajorImageVersion              resw    1
    .MinorImageVersion              resw    1
    .MajorSubsystemVersion          resw    1
    .MinorSubsystemVersion          resw    1
    .Win32VersionValue              resd    1 ; Reserved, must be zero
    .SizeOfImage                    resd    1 ; Size in bytes
    .SizeOfHeaders                  resd    1
    .CheckSum                       resd    1
    .Subsystem                      resw    1
    .DllCharacteristics             resw    1
    .SizeOfStackReserve             resd    1
    .SizeOfStackCommit              resd    1
    .SizeOfHeapReserve              resd    1
    .SizeOfHeapCommit               resd    1
    .LoaderFlags                    resd    1 ; Reserved, must be zero
    .NumberOfRvaAndSizes            resd    1
endstruc

; IMAGE_SECTION_HEADER
struc SectionHeader
    .Name                       resb    8
    .VirtualSize                resd    1
    .VirtualAddress             resd    1 ; Actually RVA from image base
    .SizeOfRawData              resd    1
    .PointerToRawData           resd    1
    .PointerToRelocations       resd    1
    .PointerToLineNumbers       resd    1
    .NumberOfRelocations        resw    1
    .NumberOfLineNumbers        resw    1
    .Characteristics            resd    1
endstruc

; IMAGE_IMPORT_DESCRIPTOR
struc ImportDescriptor
    .OriginalFirstThunk     resd    1 ; RVA to the import lookup table (on disk)
    .TimeDateStamp          resd    1
    .ForwarderChain         resd    1
    .Name                   resd    1
    .FirstThunk             resd    1 ; RVA to the import address table (on memory - real addresses
                                      ;     on disk - same as lookup table)
endstruc

%endif  ; __PE_DEFS
