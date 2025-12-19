#include <windows.h>
#include <fstream>
#include <vector>
#include <iostream>

DWORD Align(DWORD Value, DWORD Alignment)
{
    return (Value + Alignment - 1) & ~(Alignment - 1);
}

int main(int argc, char** argv)
{
    if (argc < 3)
    {
        std::cout << "Uso: AddSection.exe <input.exe> <output.exe>\n";
        return 1;
    }

    const char* inFile = argv[1];
    const char* outFile = argv[2];

    // --- Cargar archivo completo ---
    std::ifstream in(inFile, std::ios::binary);
    if (!in)
    {
        std::cout << "Error abriendo archivo.\n";
        return 1;
    }

    std::vector<BYTE> data((std::istreambuf_iterator<char>(in)),
        std::istreambuf_iterator<char>());
    in.close();

    BYTE* base = data.data();

    // --- DOS Header ---
    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)base;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE)
    {
        std::cout << "DOS header invalido.\n";
        return 1;
    }

    // --- NT Headers ---
    IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE)
    {
        std::cout << "NT header invalido.\n";
        return 1;
    }

    bool is64 = (nt->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC);
    DWORD sectionAlignment = nt->OptionalHeader.SectionAlignment;
    DWORD fileAlignment = nt->OptionalHeader.FileAlignment;

    // --- Localizar última sección ---
    IMAGE_SECTION_HEADER* sec = IMAGE_FIRST_SECTION(nt);
    IMAGE_SECTION_HEADER* last = sec + (nt->FileHeader.NumberOfSections - 1);

    DWORD lastVA = last->VirtualAddress +
        Align(last->Misc.VirtualSize, sectionAlignment);

    DWORD lastRAW = last->PointerToRawData +
        Align(last->SizeOfRawData, fileAlignment);

    // --- Crear nueva sección ---
    IMAGE_SECTION_HEADER* newSec = sec + nt->FileHeader.NumberOfSections;
    ZeroMemory(newSec, sizeof(IMAGE_SECTION_HEADER));

    memcpy(newSec->Name, ".hmx", 4);

    DWORD newSize = 0x1000;
    DWORD newRawSize = Align(newSize, fileAlignment);

    newSec->Misc.VirtualSize = newSize;
    newSec->VirtualAddress = Align(lastVA, sectionAlignment);
    newSec->SizeOfRawData = newRawSize;
    newSec->PointerToRawData = Align(lastRAW, fileAlignment);
    newSec->Characteristics = IMAGE_SCN_CNT_CODE |
        IMAGE_SCN_MEM_EXECUTE |
        IMAGE_SCN_MEM_READ |
        IMAGE_SCN_MEM_WRITE;

    // --- Expandir archivo ---
    size_t oldSize = data.size();
    size_t newFileSize = newSec->PointerToRawData + newRawSize;

    if (newFileSize > oldSize)
        data.resize(newFileSize, 0x00);

    base = data.data(); // actualizar pointer

    // --- Actualizar PE globales ---
    nt = (IMAGE_NT_HEADERS*)(base + dos->e_lfanew); // re-evaluar por seguridad
    sec = IMAGE_FIRST_SECTION(nt);

    nt->FileHeader.NumberOfSections++;

    nt->OptionalHeader.SizeOfImage =
        Align(newSec->VirtualAddress + newSec->Misc.VirtualSize, sectionAlignment);

    // --- Recalcular SizeOfHeaders ---
    DWORD sectionTableEnd =
        dos->e_lfanew +
        sizeof(DWORD) +
        sizeof(IMAGE_FILE_HEADER) +
        nt->FileHeader.SizeOfOptionalHeader +
        (nt->FileHeader.NumberOfSections * sizeof(IMAGE_SECTION_HEADER));

    nt->OptionalHeader.SizeOfHeaders = Align(sectionTableEnd, fileAlignment);

    // --- Eliminar Security Directory para evitar errores ---
    nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].VirtualAddress = 0;
    nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].Size = 0;

    // --- Guardar archivo resultante ---
    std::ofstream out(outFile, std::ios::binary | std::ios::trunc);
    if (!out)
    {
        std::cout << "No se pudo escribir archivo de salida.\n";
        return 1;
    }

    out.write((char*)data.data(), data.size());
    out.close();

    std::cout << "[OK] Sección agregada correctamente.\n";
    std::cout << "Nueva RVA:  0x" << std::hex << newSec->VirtualAddress << "\n";
    std::cout << "Nuevo RAW:  0x" << std::hex << newSec->PointerToRawData << "\n";
    std::cout << "Size:       0x" << std::hex << newSec->Misc.VirtualSize << "\n";

    return 0;
}
