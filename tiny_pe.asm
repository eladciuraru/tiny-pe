[BITS 32]

%include "pe_defs.inc"


IMAGE_BASE_ADDR     equ     0x00400000
SECTION_ALIGN       equ     0x1000
FILE_ALIGN          equ     0x200

%define RVA(Label) ((Label) - IMAGE_BASE_ADDR)


; IMAGE_DOS_HEADER
DOS_HEADER istruc DosHeader
    at DosHeader.e_magic,  dw IMAGE_DOS_SIGNATURE
    at DosHeader.e_lfanew, dd DosHeader_size
iend

; NT Headers
; PE signature
PE_SIG dd IMAGE_NT_SIGNATURE

; IMAGE_FILE_HEADER
FILE_HEADER istruc FileHeader
    at FileHeader.Machine,              dw IMAGE_FILE_MACHINE_I386
    at FileHeader.NumberOfSections,     dw 0x0001
    at FileHeader.SizeOfOptionalHeader, dw OPTIONAL_HEADER_SIZE
    at FileHeader.Characteristics,      dw IMAGE_FILE_EXECUTABLE_IMAGE | IMAGE_FILE_32BIT_MACHINE
iend

; IMAGE_OPTIONAL_HEADER
OPTIONAL_HEADER istruc OptionalHeader32
    at OptionalHeader32.Magic,                  dw IMAGE_NT_OPTIONAL_HDR32_MAGIC
    ; at OptionalHeader32.SizeOfCode,             dd SECTION_SIZE
    at OptionalHeader32.AddressOfEntryPoint,    dd RVA(EntryPoint)
    at OptionalHeader32.BaseOfCode,             dd RVA(EntryPoint)
    at OptionalHeader32.ImageBase,              dd IMAGE_BASE_ADDR
    at OptionalHeader32.SectionAlignment,       dd SECTION_ALIGN
    at OptionalHeader32.FileAlignment,          dd FILE_ALIGN
    at OptionalHeader32.MajorSubsystemVersion,  dd 5   ; WINDOWS (x86) 5.01
    at OptionalHeader32.SizeOfImage,            dd 2 * SECTION_ALIGN
    at OptionalHeader32.SizeOfHeaders,          dd HEADERS_SIZE
    at OptionalHeader32.Subsystem,              dw IMAGE_SUBSYSTEM_WINDOWS_CUI
    at OptionalHeader32.DllCharacteristics,     dw IMAGE_DLLCHARACTERISTICS_NO_SEH
    at OptionalHeader32.SizeOfStackReserve,     dd 0x100000
    at OptionalHeader32.SizeOfStackCommit,      dd 0x1000
    at OptionalHeader32.SizeOfHeapReserve,      dd 0x100000
    at OptionalHeader32.SizeOfHeapCommit,       dd 0x1000
    at OptionalHeader32.NumberOfRvaAndSizes,    dd IMAGE_NUMBEROF_DIRECTORY_ENTRIES
iend
; IMAGE_DATA_DIRECTORY[16]
DD_EXPORT_ENTRY istruc DataDirectoryEntry
iend
DD_IMPORT_ENTRY istruc DataDirectoryEntry
    at DataDirectoryEntry.VirtualAddress,   dd RVA(IMP_DESC_KERNEL32)
    at DataDirectoryEntry.Size,             dd IMPORT_DIRECTORY_SIZE
iend
times DataDirectoryEntry_size * (IMAGE_NUMBEROF_DIRECTORY_ENTRIES - 2) db 0
OPTIONAL_HEADER_SIZE        equ     $ - OPTIONAL_HEADER

; IMAGE_SECTION_HEADER
SECTION_HEADER istruc SectionHeader
    at SectionHeader.Name,               db ".MyPE", 0
    at SectionHeader.VirtualSize,        dd SECTION_ALIGN
    at SectionHeader.VirtualAddress,     dd SECTION_ALIGN
    at SectionHeader.SizeOfRawData,      dd FILE_ALIGN
    at SectionHeader.PointerToRawData,   dd FILE_ALIGN
    at SectionHeader.Characteristics,    dd IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | \
                                            IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE
iend

HEADERS_SIZE    equ     $ - $$

section progbits vstart=(IMAGE_BASE_ADDR + SECTION_ALIGN) align=FILE_ALIGN
SECTION_START:

EntryPoint:
    push 0        ; uType
    push Caption  ; lpCaption
    push Text     ; lpText
    push 0        ; hWnd
    call [MessageBoxA]

    push  byte 42
    call [ExitProcess]

; Include the data in the executable section to decrease size
Text    db "Some text", 0
Caption db "Some caption", 0

; Import Directory
; IMAGE_IMPORT_DESCRIPTOR array
IMP_DESC_KERNEL32 istruc ImportDescriptor
    at ImportDescriptor.OriginalFirstThunk, dd RVA(KERNEL32_LOOKUP_TABLE)
    at ImportDescriptor.Name,               dd RVA(KERNEL32_DLL_NAME)
    at ImportDescriptor.FirstThunk,         dd RVA(KERNEL32_IA_TABLE)
iend
IMP_DESC_USER32 istruc ImportDescriptor
    at ImportDescriptor.OriginalFirstThunk, dd RVA(USER32_LOOKUP_TABLE)
    at ImportDescriptor.Name,               dd RVA(USER32_DLL_NAME)
    at ImportDescriptor.FirstThunk,         dd RVA(USER32_IA_TABLE)
iend
istruc ImportDescriptor  ; Terminate import descriptor array
iend


; DLL Names
KERNEL32_DLL_NAME db 'kernel32.dll', 0
USER32_DLL_NAME   db 'user32.dll', 0


; Hint/Name Table
EXIT_PROCESS_NAME:
    dw 0  ; hint
    db 'ExitProcess', 0
align 2, db 0

MESSAGE_BOX_A_NAME:
    dw 0  ; hint
    db 'MessageBoxA', 0
align 2, db 0


; Import Lookup Table
KERNEL32_LOOKUP_TABLE:
    dd  RVA(EXIT_PROCESS_NAME)
    dd  0  ; End of table

USER32_LOOKUP_TABLE:
    dd  RVA(MESSAGE_BOX_A_NAME)
    dd  0  ; End of table


; Import Address Table
KERNEL32_IA_TABLE:
    ExitProcess dd  RVA(EXIT_PROCESS_NAME)
                dd  0  ; End of table
USER32_IA_TABLE:
    MessageBoxA dd  RVA(MESSAGE_BOX_A_NAME)
                dd  0  ; End of table
IMPORT_DIRECTORY_SIZE       equ     $ - IMP_DESC_KERNEL32
align FILE_ALIGN, db 0


SECTION_SIZE    equ     $ - SECTION_START
