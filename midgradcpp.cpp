#include <iostream>
#include <fstream>
#include <Windows.h>
using namespace std;

DWORD RvaToAbs(DWORD virtualAddress, DWORD sectionSize, IMAGE_SECTION_HEADER* sections, int sectionsCount) {
    for (int i = 0; i < sectionsCount; i++) {
        DWORD start = sections[i].VirtualAddress;
        DWORD size = sections[i].Misc.VirtualSize;

        int fullSections = size / sectionSize;
        int totalSections = fullSections * sectionSize < size ? fullSections + 1 : fullSections;

        DWORD end = start + totalSections * sectionSize;

        if (virtualAddress >= start && virtualAddress < end) {
            return virtualAddress - sections[i].VirtualAddress + sections[i].PointerToRawData;
        }
    }

    return 0;
}

DWORD alignAddress(DWORD address, DWORD alingmentSize) {
    float sectionCount = (float)address / alingmentSize;
    return (DWORD)(ceilf(sectionCount) * alingmentSize);
}

int main(int argc, char* argv[]) {
    if (argc != 2) {
        cout << "Enter executable name";
        return 1;
    }

    char* executableName = argv[1];
    cout << "Opening: " << executableName << endl;

    ifstream file(executableName, ios::in | ios::binary | ios::ate);
    if (!file.is_open()) {
		char e[255];
		strerror_s(e, errno);
		cout << "Failed to open file: " << e;
        return 1;
    }

    streampos size = file.tellg();
    char* fileBytes = new char[size];

    file.seekg(0, ios::beg);
    file.read(fileBytes, size);
    file.close();

    //TODO check size
    IMAGE_DOS_HEADER* dosHeader = (IMAGE_DOS_HEADER*)fileBytes;

    if (dosHeader->e_magic != 0x5A4D) {
        cout << "Not a valid executable specified\n";
        return 1;
    }

    LONG peHeaderOffset = dosHeader->e_lfanew;
    IMAGE_NT_HEADERS* peHeader = (IMAGE_NT_HEADERS*)(fileBytes + peHeaderOffset);

    if (peHeader->Signature != 0x4550) {
        cout << "Not a valid executable, pe header signature validation error\n";
        return 1;
    }

    IMAGE_DATA_DIRECTORY* importTableInfo = &peHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];

    IMAGE_SECTION_HEADER* sections = (IMAGE_SECTION_HEADER*)(fileBytes + peHeaderOffset + sizeof(IMAGE_NT_HEADERS));
    DWORD sectionAlignment = peHeader->OptionalHeader.SectionAlignment;
    WORD sectionCount = peHeader->FileHeader.NumberOfSections;

    DWORD absImportAddress = RvaToAbs(importTableInfo->VirtualAddress, sectionAlignment, sections, sectionCount);

    if (!absImportAddress) {
        cout << "Error finding import table\n";
        return 1;
    }

    IMAGE_IMPORT_DESCRIPTOR* imports = (IMAGE_IMPORT_DESCRIPTOR*)(fileBytes + absImportAddress);
    int importsCount = 0;

    for (int i = 0; imports[i].OriginalFirstThunk != 0; i++)
    {
        DWORD nameAddress = RvaToAbs(imports[i].Name, sectionAlignment, sections, sectionCount);
        char* name = (char*)(fileBytes + nameAddress);
        cout << name << ":\n";

        DWORD nameTableAddr = RvaToAbs(imports[i].OriginalFirstThunk, sectionAlignment, sections, sectionCount);
        IMAGE_THUNK_DATA* nameTables = (IMAGE_THUNK_DATA*)(fileBytes + nameTableAddr);
        IMAGE_THUNK_DATA* nTables = (IMAGE_THUNK_DATA*)(fileBytes + RvaToAbs(imports[i].FirstThunk, sectionAlignment, sections, sectionCount));

        for (int j = 0; nameTables[j].u1.Ordinal != 0; j++) {

            if (nameTables[j].u1.Ordinal & IMAGE_ORDINAL_FLAG) {
                DWORD ord = (DWORD)(nameTables[j].u1.Ordinal && 0xFFFF);
                cout << "\t" << ord << "\n";
            }
            else {
                // 32 / 64 diff addresses check
                DWORD nAddress = RvaToAbs((DWORD)nameTables[j].u1.AddressOfData, sectionAlignment, sections, sectionCount);
                IMAGE_IMPORT_BY_NAME* byName = (IMAGE_IMPORT_BY_NAME*)(fileBytes + nAddress);
                cout << "\t" << byName->Name << "\n";
            }
        }

        importsCount = i + 1;
    }

    // modify
    DWORD originalDeclaredHeaderSize = peHeader->OptionalHeader.SizeOfHeaders;
	DWORD originalActualHeaderSize = (DWORD)((char*)&sections[sectionCount] - fileBytes);
    DWORD updatedActualHeaderSize = originalActualHeaderSize + sizeof(IMAGE_SECTION_HEADER);
    int sizeDiff = updatedActualHeaderSize - originalDeclaredHeaderSize;

    int headerSizeIncrease = 0;
    if (sizeDiff > 0) {
        headerSizeIncrease = alignAddress(sizeDiff, peHeader->OptionalHeader.FileAlignment);
    }

    DWORD updatedDeclaredHeaderSize = originalDeclaredHeaderSize + headerSizeIncrease;

    DWORD sectionsEndVA = 0;

    for (int i = 0; i < sectionCount; i++) {
        DWORD sectionEndVA = sections[i].VirtualAddress + sections[i].Misc.VirtualSize;
        if (sectionsEndVA < sectionEndVA) {
            sectionsEndVA = sectionEndVA;
        }

        sections[i].PointerToRawData += headerSizeIncrease;
    }
    
    sectionsEndVA = alignAddress(sectionsEndVA, sectionAlignment);

    absImportAddress;
    importTableInfo->Size;

    // NOTE: Assuming parsing the dll export talbe is not in the scope of the task.
    DWORD sectionPos = (DWORD)sectionsEndVA;

    //const char* dllName = "dll.dll";
    const char* dllName = "lua511.dll";
    DWORD dllNameAddress = sectionPos;
    sectionPos += (DWORD)(strlen(dllName) + 1);

    //const WORD hint = 0;
    const WORD hint = 0;
    DWORD hintAddress = sectionPos;
    sectionPos += sizeof(WORD);

    //const char* functionName = "?callMe@@YAXXZ";
    const char* functionName = "lua_call";
    DWORD funcNameAddress = sectionPos;
    sectionPos += (DWORD)(strlen(functionName) + 1);
    
    IMAGE_THUNK_DATA newThunks[4]{};
    DWORD newThunksAddress = sectionPos;
    sectionPos += sizeof(IMAGE_THUNK_DATA) * 4;

    newThunks[0].u1.AddressOfData = hintAddress;
    newThunks[1].u1.AddressOfData = 0;
    newThunks[2].u1.AddressOfData = hintAddress;
    newThunks[3].u1.AddressOfData = 0;

    DWORD importInfoSize = sectionPos - sectionsEndVA;
    DWORD totalSectionSize = importInfoSize + sizeof(IMAGE_IMPORT_DESCRIPTOR) + importTableInfo->Size;

    IMAGE_IMPORT_DESCRIPTOR descriptor{};
    descriptor.OriginalFirstThunk = newThunksAddress;
    descriptor.FirstThunk = newThunksAddress + (sizeof(IMAGE_THUNK_DATA) * 2);
    descriptor.Name = dllNameAddress;

    IMAGE_SECTION_HEADER newSectionHeader{};
    const char* sectionName = ".newImp";
    memcpy(newSectionHeader.Name, ".newImp", 7);
    newSectionHeader.PointerToRawData = (DWORD)size + headerSizeIncrease;
    newSectionHeader.SizeOfRawData = alignAddress(totalSectionSize, peHeader->OptionalHeader.FileAlignment);
    newSectionHeader.VirtualAddress = sectionsEndVA;
    newSectionHeader.Misc.VirtualSize = alignAddress(totalSectionSize, sectionAlignment);
    newSectionHeader.Characteristics = IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ;

    DWORD lastSectionHeaderOffset = (DWORD)((char*)&sections[peHeader->FileHeader.NumberOfSections] - fileBytes);

    peHeader->FileHeader.NumberOfSections++;
    peHeader->OptionalHeader.SizeOfHeaders = updatedDeclaredHeaderSize;
    peHeader->OptionalHeader.SizeOfImage = newSectionHeader.VirtualAddress + newSectionHeader.Misc.VirtualSize;
    importTableInfo->VirtualAddress = newSectionHeader.VirtualAddress + importInfoSize;
    importTableInfo->Size += sizeof(IMAGE_IMPORT_DESCRIPTOR);

    ofstream outFile(".\\testpe\\out.exe", ios::out | ios::binary | ios::trunc);
    if (!outFile.is_open()) {
		char e[255];
		strerror_s(e, errno);
		cout << "Failed to open file to write output: " << e;
        return 1;
    }

    outFile.write(fileBytes, lastSectionHeaderOffset);
    outFile.write((char*)&newSectionHeader, sizeof(IMAGE_SECTION_HEADER));

    char z = 0;
    while (outFile.tellp() < updatedDeclaredHeaderSize){
        outFile.write(&z, sizeof(char));
    }

    outFile.write(fileBytes + originalDeclaredHeaderSize, (int)size - originalDeclaredHeaderSize);

    //new section start
    outFile.write(dllName, strlen(dllName));
    outFile.write(&z, sizeof(char));
    // IMAGE INPORT BY NAME
    outFile.write((char*)&hint, sizeof(WORD));
    outFile.write(functionName, strlen(functionName));
    outFile.write(&z, sizeof(char));
    outFile.write((char*)newThunks, sizeof(IMAGE_THUNK_DATA) * 4);

    for (int i = 0; imports[i].OriginalFirstThunk != 0; i++) {
		outFile.write((char*)&imports[i], sizeof(IMAGE_IMPORT_DESCRIPTOR));
    }
	outFile.write((char*)&descriptor, sizeof(IMAGE_IMPORT_DESCRIPTOR));

    for (DWORD i = 0; i < sizeof(IMAGE_IMPORT_DESCRIPTOR); i++) {
        //outFile.write(&z, sizeof(char));
    }
    for (DWORD i = 0; i < sizeof(IMAGE_IMPORT_DESCRIPTOR); i++) {
        outFile.write(&z, sizeof(char));
    }

    while (outFile.tellp() < newSectionHeader.PointerToRawData + newSectionHeader.SizeOfRawData) {
        outFile.write(&z, sizeof(char));
    }
    outFile.close();

    return 0;
}
