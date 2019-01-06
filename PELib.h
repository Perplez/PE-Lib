#include <windows.h>
typedef struct tagImportTableInfo{
    DWORD NumberOfImports;
    PIMAGE_IMPORT_DESCRIPTOR ImportInfo;
} IMAGE_IMPORT_DESCRIPTOR_INFO, *PIMAGE_IMPORT_DESCRIPTOR_INFO;
typedef struct tagPE_Information{
    PIMAGE_OPTIONAL_HEADER OptionalHeader;
    DWORD NumberOfImportDescriptors;
    DWORD NumberOfSections;
    PIMAGE_IMPORT_DESCRIPTOR_INFO *ImportDescriptor;
    PIMAGE_SECTION_HEADER *Sections;
}PE_INFORMATION, *PPE_INFORMATION;
int WINAPI ParseRawImage(unsigned char *ImageBase, PPE_INFORMATION PEInformation);
int UnParseRawImage(PPE_INFORMATION PEInformation);
int WINAPI FindRawAddress(unsigned char *ImageBase, DWORD Address);
int WINAPI FindRVAAddress(unsigned char *ImageBase, DWORD RVAAddress);
int WINAPI AddFunctionToImage(HANDLE hInitialFile);
int WINAPI ParseRawImage(unsigned char *ImageBase, PPE_INFORMATION PEInformation){
    unsigned char *PESignature, *ImportTable, *SectionEntry, *ThunkTable;
    PESignature = ImportTable = ImageBase;
    PESignature += *(DWORD *)(ImageBase + 0x3c);
    ImportTable += FindRawAddress(ImageBase, *(DWORD *)(PESignature + 0x80));
    SectionEntry = PESignature + 0xf8;
    PEInformation->OptionalHeader = (PIMAGE_OPTIONAL_HEADER)(PESignature + 0x18);
    PEInformation->NumberOfSections = *(WORD *)(PESignature + 0x6);
    PEInformation->Sections = (PIMAGE_SECTION_HEADER *)VirtualAlloc(0, 4 * PEInformation->NumberOfSections, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    for(int i = 0;i <= PEInformation->NumberOfSections - 1;i++, SectionEntry += 0x28){
        PEInformation->Sections[i] = (PIMAGE_SECTION_HEADER)SectionEntry;
    }
    for(int i = 0;NULL != *(DWORD *)(ImportTable + 0x10 + (i * 0x14));i++) PEInformation->NumberOfImportDescriptors++;
    PEInformation->ImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR_INFO *)VirtualAlloc(0, 4 * PEInformation->NumberOfImportDescriptors + sizeof(IMAGE_IMPORT_DESCRIPTOR_INFO) * PEInformation->NumberOfImportDescriptors, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    for (int i = 0, size = PEInformation->NumberOfImportDescriptors * 4;i <= (PEInformation->NumberOfImportDescriptors - 1);i++){
        PEInformation->ImportDescriptor[i] = (PIMAGE_IMPORT_DESCRIPTOR_INFO)(PEInformation->ImportDescriptor + size + (sizeof(IMAGE_IMPORT_DESCRIPTOR_INFO) * i));
    }
    for(int i = 0;i <= (PEInformation->NumberOfImportDescriptors - 1);i++){
        PEInformation->ImportDescriptor[i]->ImportInfo = (PIMAGE_IMPORT_DESCRIPTOR)ImportTable;
        ThunkTable = ImageBase + FindRawAddress(ImageBase, PEInformation->ImportDescriptor[i]->ImportInfo->FirstThunk);
        for(;NULL != *(DWORD *)ThunkTable;ThunkTable += 4) PEInformation->ImportDescriptor[i]->NumberOfImports++;
        ImportTable += 0x14;
    }
    return TRUE;
}
PIMAGE_SECTION_HEADER AddSectionToImage(unsigned char *ImageBase, const char *NameOfSection, DWORD VirtualSize, DWORD RawSize);
PIMAGE_SECTION_HEADER AddSectionToImage(unsigned char *ImageBase, const char *NameOfSection, DWORD VirtualSize, DWORD RawSize, DWORD Flags){
    unsigned char *PESignature = ImageBase, *SectionEntry;
    PIMAGE_OPTIONAL_HEADER32 OptionalHeader;
    DWORD NumberOfSections;
    if (strlen(NameOfSection) > 8) return FALSE;
    PESignature += *(DWORD *)(ImageBase + 0x3c);
    SectionEntry = PESignature + 0xf8;
    OptionalHeader = (PIMAGE_OPTIONAL_HEADER32)(PESignature + 0x18);
    NumberOfSections = (*(WORD *)(PESignature + 0x6));
    PIMAGE_SECTION_HEADER SectionHeader;
    SectionHeader = (PIMAGE_SECTION_HEADER)SectionEntry;
    SectionEntry += 0x28 * NumberOfSections;
    memcpy(SectionEntry, NameOfSection, strlen(NameOfSection));
    *(DWORD *)(SectionEntry + 0x8) = VirtualSize;
    for (int i = 1;;i++){
        if (SectionHeader[NumberOfSections - 1].Misc.VirtualSize > OptionalHeader->SectionAlignment * i) continue;
        *(DWORD *)(SectionEntry + 0xc) = SectionHeader[NumberOfSections - 1].VirtualAddress + OptionalHeader->SectionAlignment * i;
        break;
    }
    for (int i = 1;;i++){
        if (RawSize > OptionalHeader->FileAlignment * i) continue;
        *(DWORD *)(SectionEntry + 0x10) = OptionalHeader->FileAlignment * i;
        break;
    }
    *(DWORD *)(SectionEntry + 0x14) = SectionHeader[NumberOfSections - 1].PointerToRawData + SectionHeader[NumberOfSections - 1].SizeOfRawData;
    *(DWORD *)(SectionEntry + 0x24) = Flags;
    *(WORD *)(PESignature + 0x6) += 1;
    if (Flags & IMAGE_SCN_CNT_INITIALIZED_DATA == IMAGE_SCN_CNT_INITIALIZED_DATA) OptionalHeader->SizeOfInitializedData += SectionHeader[NumberOfSections].SizeOfRawData;
    else OptionalHeader->SizeOfUninitializedData += SectionHeader[NumberOfSections].SizeOfRawData;
    if (Flags & IMAGE_SCN_CNT_CODE == IMAGE_SCN_CNT_CODE) OptionalHeader->SizeOfCode += SectionHeader[NumberOfSections].SizeOfRawData;
    for (int i = 1;;i++){
        if (VirtualSize > OptionalHeader->SectionAlignment * i) continue;
        OptionalHeader->SizeOfImage += OptionalHeader->SectionAlignment * i;
        break;
    }
    unsigned char *Sec = (unsigned char *)VirtualAlloc(0, 0x24, MEM_COMMIT, PAGE_READWRITE);
    memcpy(Sec, SectionEntry, 0x24);
    return (PIMAGE_SECTION_HEADER)Sec;
}
int UnParseRawImage(PPE_INFORMATION PEInformation){
    VirtualFree(PEInformation->Sections, 4 * PEInformation->NumberOfSections, MEM_DECOMMIT);
    VirtualFree(PEInformation->ImportDescriptor, 4 * PEInformation->NumberOfImportDescriptors, MEM_DECOMMIT);
    return TRUE;
}
int WINAPI FindRawAddress(unsigned char *ImageBase, DWORD Address){
    DWORD NumberOfSections = 0;
    unsigned char *PESignature;
    PESignature = ImageBase + *(DWORD *)(ImageBase + 0x3c);
    NumberOfSections = *(WORD *)(PESignature + 0x6);
    NumberOfSections -= 1;
    PESignature += 0xf8; // Base of Headers;
    while(NumberOfSections >= 0){
        if (Address >= (*(DWORD *)((PESignature + (NumberOfSections * 0x28)) + 12))){
            Address -= *(DWORD *)((PESignature + (NumberOfSections * 0x28)) + 12);
            Address += *(DWORD *)((PESignature + (NumberOfSections * 0x28)) + 0x14);
            return Address;
        }
        NumberOfSections--;
    }
    return 0;
}
int WINAPI FindRVAAddress(unsigned char *ImageBase, DWORD Address){
    DWORD NumberOfSections = 0;
    unsigned char *PESignature, *SectionEntry;
    PESignature = ImageBase + *(DWORD *)(ImageBase + 0x3c);
    SectionEntry = PESignature + 0xf8;
    NumberOfSections = *(WORD *)(PESignature + 0x6);
    NumberOfSections -= 1;
    while(NumberOfSections >= 0){
        if (Address >= FindRawAddress(ImageBase, *(DWORD *)(0xc + NumberOfSections * 0x28 + SectionEntry))){
            Address -= *(DWORD *)(0x14 + NumberOfSections * 0x28 + SectionEntry);
            Address += *(DWORD *)(0xc + NumberOfSections * 0x28 + SectionEntry);
            return Address;
        }
    NumberOfSections--;
    }
    return 0;
}
int WINAPI AddFunctionToImage(HANDLE hInitialFile, const char *FunctionName, const char *DllName){
    unsigned char *MappedFile, *PESignature, *NewImportTable, *ImportTable;
    BY_HANDLE_FILE_INFORMATION FileInfo;
    DWORD Padding, SizeOfFinalIAT;
    Padding = 0;
    PPE_INFORMATION PEInformation = (PPE_INFORMATION)VirtualAlloc(0, sizeof(PE_INFORMATION), MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    PIMAGE_SECTION_HEADER AddedSection;
    if (GetFileInformationByHandle(hInitialFile, &FileInfo) == 0) return 0;
    HANDLE hMap = CreateFileMappingA(hInitialFile, NULL, PAGE_READWRITE | SEC_COMMIT, NULL, FileInfo.nFileSizeLow, NULL);
    MappedFile = (unsigned char *)MapViewOfFile(hMap, FILE_MAP_ALL_ACCESS, NULL, NULL, NULL);
    ParseRawImage(MappedFile, PEInformation);
    AddedSection = AddSectionToImage(MappedFile, ".pwned", SizeOfFinalIAT, SizeOfFinalIAT,
    IMAGE_SCN_ALIGN_4BYTES | IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE);
    UnmapViewOfFile((LPCVOID)MappedFile);
    CloseHandle(hMap);
    hMap = CreateFileMappingA(hInitialFile, NULL, PAGE_READWRITE | SEC_COMMIT, NULL, FileInfo.nFileSizeLow + AddedSection->SizeOfRawData, NULL);
    MappedFile = (unsigned char *)MapViewOfFile(hMap, FILE_MAP_ALL_ACCESS, NULL, NULL, NULL);
    PESignature = MappedFile + *(DWORD *)(MappedFile + 0x3c);
    SizeOfFinalIAT = 0x14 * PEInformation->NumberOfImportDescriptors;
    if (SizeOfFinalIAT % 2 != NULL) Padding++;
    SizeOfFinalIAT += 0x14 * 2 + 8 + 2 + strlen(FunctionName) + 1 + Padding + strlen(DllName) + 1;
    ImportTable = NewImportTable = MappedFile + AddedSection->PointerToRawData;
    *(DWORD *)(PESignature + 0x80) = FindRVAAddress(MappedFile, NewImportTable - MappedFile);
    *(DWORD *)(PESignature + 0x84) = 0x14 * 2 + 0x14 * PEInformation->NumberOfImportDescriptors;
    memset(NewImportTable, '\0', SizeOfFinalIAT);
    ImportTable += SizeOfFinalIAT;
    memcpy(NewImportTable, PEInformation->ImportDescriptor[0]->ImportInfo, 0x14 * PEInformation->NumberOfImportDescriptors);
    NewImportTable += 0x14 * PEInformation->NumberOfImportDescriptors;
    ImportTable -= strlen(DllName) + 1;
    memcpy(ImportTable, DllName, strlen(DllName) + 1);
    *(DWORD *)(NewImportTable + 0xc) = FindRVAAddress(MappedFile, ImportTable - MappedFile);
    ImportTable -= 2 + strlen(FunctionName) + 1 + Padding;
    memcpy(ImportTable + 2, FunctionName, strlen(FunctionName) + 1 + Padding);
    *(DWORD *)(ImportTable - 8) = FindRVAAddress(MappedFile, ImportTable - MappedFile);
    ImportTable -= 8;
    *(DWORD *)(NewImportTable + 0x10) = FindRVAAddress(MappedFile, ImportTable - MappedFile);
    UnParseRawImage(PEInformation);
    VirtualFree(AddedSection, 0x24, MEM_DECOMMIT);
    UnmapViewOfFile(MappedFile);
    CloseHandle(hMap);
    return 0;
}
