#include <iostream>
#include <fstream>
#include <Windows.h>
using namespace std;

bool is32Bit(IMAGE_NT_HEADERS* header) {
    return header->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC;
}

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

void printFuncImports32(char* file, DWORD address, DWORD sectionAlignment, IMAGE_SECTION_HEADER* sections, int sectionCount) {
	IMAGE_THUNK_DATA32* nameTables = (IMAGE_THUNK_DATA32*)(file + address);

	for (int j = 0; nameTables[j].u1.Ordinal != 0; j++) {

		if (nameTables[j].u1.Ordinal & IMAGE_ORDINAL_FLAG32) {
			DWORD ord = (DWORD)(nameTables[j].u1.Ordinal && 0xFFFF);
			cout << "\t" << ord << "\n";
		}
		else {
			DWORD nAddress = RvaToAbs((DWORD)nameTables[j].u1.AddressOfData, sectionAlignment, sections, sectionCount);
			IMAGE_IMPORT_BY_NAME* byName = (IMAGE_IMPORT_BY_NAME*)(file + nAddress);
			cout << "\t" << byName->Name << "\n";
		}
	}
}

void printFuncImports64(char* file, DWORD address, DWORD sectionAlignment, IMAGE_SECTION_HEADER* sections, int sectionCount) {
	IMAGE_THUNK_DATA64* nameTables = (IMAGE_THUNK_DATA64*)(file + address);

	for (int j = 0; nameTables[j].u1.Ordinal != 0; j++) {

		if (nameTables[j].u1.Ordinal & IMAGE_ORDINAL_FLAG64) {
			DWORD ord = (DWORD)(nameTables[j].u1.Ordinal && 0xFFFF);
			cout << "\t" << ord << "\n";
		}
		else {
			DWORD nAddress = RvaToAbs((DWORD)nameTables[j].u1.AddressOfData, sectionAlignment, sections, sectionCount);
			IMAGE_IMPORT_BY_NAME* byName = (IMAGE_IMPORT_BY_NAME*)(file + nAddress);
			cout << "\t" << byName->Name << "\n";
		}
	}
}

int getNtHeaderSize(IMAGE_NT_HEADERS* header) {
    return is32Bit(header) ? sizeof(IMAGE_NT_HEADERS32) : sizeof(IMAGE_NT_HEADERS64);
}

IMAGE_DATA_DIRECTORY* getImportDataDirectory(IMAGE_NT_HEADERS* header) {
    if (is32Bit(header)) {
        IMAGE_NT_HEADERS32* header32 = (IMAGE_NT_HEADERS32*)header;
        return &(header32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT]);
    }
    else {
        IMAGE_NT_HEADERS64* header64 = (IMAGE_NT_HEADERS64*)header;
        return &(header64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT]);
    }
}

DWORD getSectionAlingment(IMAGE_NT_HEADERS* header) {
    if (is32Bit(header)) {
        IMAGE_NT_HEADERS32* header32 = (IMAGE_NT_HEADERS32*)header;
        return header32->OptionalHeader.SectionAlignment;
    }
    else {
        IMAGE_NT_HEADERS64* header64 = (IMAGE_NT_HEADERS64*)header;
        return header64->OptionalHeader.SectionAlignment;
    }
}

DWORD getFileAlingment(IMAGE_NT_HEADERS* header) {
    if (is32Bit(header)) {
        IMAGE_NT_HEADERS32* header32 = (IMAGE_NT_HEADERS32*)header;
        return header32->OptionalHeader.FileAlignment;
    }
    else {
        IMAGE_NT_HEADERS64* header64 = (IMAGE_NT_HEADERS64*)header;
        return header64->OptionalHeader.FileAlignment;
    }
}

DWORD* getSizeOfHeaders(IMAGE_NT_HEADERS* header) {
    if (is32Bit(header)) {
        IMAGE_NT_HEADERS32* header32 = (IMAGE_NT_HEADERS32*)header;
        return &header32->OptionalHeader.SizeOfHeaders;
    }
    else {
        IMAGE_NT_HEADERS64* header64 = (IMAGE_NT_HEADERS64*)header;
        return &header64->OptionalHeader.SizeOfHeaders;
    }
}

DWORD* getSizeOfImage(IMAGE_NT_HEADERS* header) {
    if (is32Bit(header)) {
        IMAGE_NT_HEADERS32* header32 = (IMAGE_NT_HEADERS32*)header;
        return &header32->OptionalHeader.SizeOfImage;
    }
    else {
        IMAGE_NT_HEADERS64* header64 = (IMAGE_NT_HEADERS64*)header;
        return &header64->OptionalHeader.SizeOfImage;
    }
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

    bool is32BitPE = is32Bit(peHeader);

    IMAGE_DATA_DIRECTORY* importTableInfo = getImportDataDirectory(peHeader);

    IMAGE_SECTION_HEADER* sections = (IMAGE_SECTION_HEADER*)(fileBytes + peHeaderOffset + getNtHeaderSize(peHeader));
    DWORD sectionAlignment = getSectionAlingment(peHeader);
    DWORD fileAlignment = getFileAlingment(peHeader);
    WORD sectionCount = peHeader->FileHeader.NumberOfSections;

    DWORD absImportAddress = RvaToAbs(importTableInfo->VirtualAddress, sectionAlignment, sections, sectionCount);

    if (!absImportAddress) {
        cout << "Error finding import table\n";
        return 1;
    }

    IMAGE_IMPORT_DESCRIPTOR* imports = (IMAGE_IMPORT_DESCRIPTOR*)(fileBytes + absImportAddress);

    for (int i = 0; imports[i].OriginalFirstThunk != 0; i++)
    {
        DWORD nameAddress = RvaToAbs(imports[i].Name, sectionAlignment, sections, sectionCount);
        char* name = (char*)(fileBytes + nameAddress);
        cout << name << ":\n";

        DWORD thunkRVA = imports[i].OriginalFirstThunk ? imports[i].FirstThunk : imports[i].OriginalFirstThunk;
        DWORD nameTableAddr = RvaToAbs(thunkRVA, sectionAlignment, sections, sectionCount);
        if (is32BitPE) {
            printFuncImports32(fileBytes, nameTableAddr, sectionAlignment, sections, sectionCount);
        }
        else {
            printFuncImports64(fileBytes, nameTableAddr, sectionAlignment, sections, sectionCount);
        }
    }

    // modify
    DWORD* sizeOfImagePointer = getSizeOfImage(peHeader);
    DWORD* sizeOfHeadersPointer = getSizeOfHeaders(peHeader);
    DWORD originalDeclaredHeaderSize = *sizeOfHeadersPointer;
	DWORD originalActualHeaderSize = (DWORD)((char*)&sections[sectionCount] - fileBytes);
    DWORD updatedActualHeaderSize = originalActualHeaderSize + sizeof(IMAGE_SECTION_HEADER);
    int sizeDiff = updatedActualHeaderSize - originalDeclaredHeaderSize;

    int headerSizeIncrease = 0;
    if (sizeDiff > 0) {
        headerSizeIncrease = alignAddress(sizeDiff, fileAlignment);
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

    // NOTE: Assuming parsing the dll export talbe is not in the scope of the task.
    DWORD sectionPos = (DWORD)sectionsEndVA;

    const char* dll64 = "dll64.dll";
    const char* dll32 = "dll32.dll";

    const char* dllName = is32BitPE ? dll32 : dll64;
    DWORD dllNameAddress = sectionPos;
    sectionPos += (DWORD)(strlen(dllName) + 1);

    const WORD hint = 0;
    DWORD hintAddress = sectionPos;
    sectionPos += sizeof(WORD);

    const char* functionName = "?callMe@@YAXXZ";
    DWORD funcNameAddress = sectionPos;
    sectionPos += (DWORD)(strlen(functionName) + 1);
    
    char* thunks;

    IMAGE_THUNK_DATA32 newThunks32[4]{};
    IMAGE_THUNK_DATA64 newThunks64[4]{};
    DWORD newOriginalThunksAddress = sectionPos;
    DWORD newThunksAddress;
    DWORD thunksSize;

    if (is32BitPE) {
        thunks = (char*)newThunks32;
        thunksSize = sizeof(IMAGE_THUNK_DATA32) * 4;
		newThunks32[0].u1.AddressOfData = hintAddress;
		newThunks32[1].u1.AddressOfData = 0;
		newThunks32[2].u1.AddressOfData = hintAddress;
		newThunks32[3].u1.AddressOfData = 0;
        newThunksAddress = newOriginalThunksAddress + sizeof(IMAGE_THUNK_DATA32) * 2;
    }
    else {
        thunks = (char*)newThunks64;
        thunksSize = sizeof(IMAGE_THUNK_DATA64) * 4;
		newThunks64[0].u1.AddressOfData = hintAddress;
		newThunks64[1].u1.AddressOfData = 0;
		newThunks64[2].u1.AddressOfData = hintAddress;
		newThunks64[3].u1.AddressOfData = 0;
        newThunksAddress = newOriginalThunksAddress + sizeof(IMAGE_THUNK_DATA64) * 2;
    }

    sectionPos += thunksSize;

    DWORD importInfoSize = sectionPos - sectionsEndVA;
    DWORD totalSectionSize = importInfoSize + sizeof(IMAGE_IMPORT_DESCRIPTOR) + importTableInfo->Size;

    IMAGE_IMPORT_DESCRIPTOR descriptor{};
    descriptor.OriginalFirstThunk = newOriginalThunksAddress;
    descriptor.FirstThunk = newThunksAddress;
    descriptor.Name = dllNameAddress;

    IMAGE_SECTION_HEADER newSectionHeader{};
    const char* sectionName = ".newImp";
    memcpy(newSectionHeader.Name, ".newImp", 7);
    newSectionHeader.PointerToRawData = (DWORD)size + headerSizeIncrease;
    newSectionHeader.SizeOfRawData = alignAddress(totalSectionSize, fileAlignment);
    newSectionHeader.VirtualAddress = sectionsEndVA;
    newSectionHeader.Misc.VirtualSize = alignAddress(totalSectionSize, sectionAlignment);
    newSectionHeader.Characteristics = IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE;

    DWORD lastSectionHeaderOffset = (DWORD)((char*)&sections[peHeader->FileHeader.NumberOfSections] - fileBytes);

    peHeader->FileHeader.NumberOfSections++;
    *sizeOfHeadersPointer = updatedDeclaredHeaderSize;
    *sizeOfImagePointer = newSectionHeader.VirtualAddress + newSectionHeader.Misc.VirtualSize;
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
    outFile.write((char*)thunks, thunksSize);

    for (int i = 0; imports[i].OriginalFirstThunk != 0; i++) {
		outFile.write((char*)&imports[i], sizeof(IMAGE_IMPORT_DESCRIPTOR));
    }
	outFile.write((char*)&descriptor, sizeof(IMAGE_IMPORT_DESCRIPTOR));

    for (DWORD i = 0; i < sizeof(IMAGE_IMPORT_DESCRIPTOR); i++) {
        outFile.write(&z, sizeof(char));
    }

    while (outFile.tellp() < newSectionHeader.PointerToRawData + newSectionHeader.SizeOfRawData) {
        outFile.write(&z, sizeof(char));
    }
    outFile.close();

    delete[] fileBytes;
    return 0;
}
