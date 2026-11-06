#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

/* ==============================
   1. PE HEADER STRUCTURES
   ============================== */

#pragma pack(push, 1)

typedef struct {
    uint16_t e_magic;       // MZ signature
    uint8_t padding[58];
    uint32_t e_lfanew;      // Offset of PE header
} DOS_Header;

typedef struct {
    uint16_t machine;
    uint16_t numberofsections;
    uint32_t timedatestamp;
    uint32_t pointertosymboltable;
    uint32_t numberofsymbol;
    uint16_t sizeofoptionalheader;
    uint16_t characteristics;
} FILE_HEADER;

#pragma pack(pop)


/* ==============================
   2. READ LITTLE-ENDIAN VALUES
   ============================== */

// Read a 2-byte value
uint16_t read_u16(uint8_t *p)
{
    return p[0] | (p[1] << 8);
}

// Read a 4-byte value
uint32_t read_u32(uint8_t *p)
{
    return (uint32_t)p[0]
         | ((uint32_t)p[1] << 8)
         | ((uint32_t)p[2] << 16)
         | ((uint32_t)p[3] << 24);
}

// Read an 8-byte value
uint64_t read_u64(uint8_t *p)
{
    return (uint64_t)read_u32(p)
         | ((uint64_t)read_u32(p + 4) << 32);
}


/* ==============================
   3. MAIN PROGRAM
   ============================== */

int main(int argc, char *argv[])
{
    // Check command-line arguments
    if (argc != 2) {
        printf("Usage: %s <filename>\n", argv[0]);
        return 1;
    }

    // Open file in binary read mode
    FILE *file = fopen(argv[1], "rb");

    if (file == NULL) {
        perror("Error opening file");
        return 1;
    }

    printf("Parsing File: %s\n", argv[1]);


    /* ==============================
       STEP 1: READ DOS HEADER
       ============================== */

    DOS_Header dos_header;

    if (fread(&dos_header, sizeof(dos_header), 1, file) != 1) {
        printf("Error: Could not read DOS Header\n");
        fclose(file);
        return 1;
    }

    // Check MZ signature
    if (dos_header.e_magic != 0x5A4D) {
        printf("Error: Invalid MZ signature\n");
        fclose(file);
        return 1;
    }

    printf("\nDOS Header: Valid MZ signature\n");


    /* ==============================
       STEP 2: FIND PE HEADER
       ============================== */

    if (fseek(file, (long)dos_header.e_lfanew, SEEK_SET) != 0) {
        printf("Error: Could not find PE Header\n");
        fclose(file);
        return 1;
    }

    // Read PE signature as four raw bytes
    uint8_t pe_signature[4];

    if (fread(pe_signature, 1, 4, file) != 4) {
        printf("Error: Could not read PE signature\n");
        fclose(file);
        return 1;
    }

    if (pe_signature[0] != 'P' ||
        pe_signature[1] != 'E' ||
        pe_signature[2] != 0  ||
        pe_signature[3] != 0) {

        printf("Error: Invalid PE signature\n");
        fclose(file);
        return 1;
    }

    printf("PE Signature: Valid\n");


    /* ==============================
       STEP 3: READ COFF HEADER
       ============================== */

    FILE_HEADER file_header;

    if (fread(&file_header, sizeof(file_header), 1, file) != 1) {
        printf("Error: Could not read COFF Header\n");
        fclose(file);
        return 1;
    }

    printf("\n========== COFF FILE HEADER ==========\n");

    printf("Machine:                  0x%04X\n",
           file_header.machine);

    printf("Number of Sections:       %u\n",
           file_header.numberofsections);

    printf("Time Date Stamp:          0x%08X\n",
           file_header.timedatestamp);

    printf("Pointer to Symbol Table:  0x%08X\n",
           file_header.pointertosymboltable);

    printf("Number of Symbols:        %u\n",
           file_header.numberofsymbol);

    printf("Optional Header Size:     %u bytes\n",
           file_header.sizeofoptionalheader);

    printf("Characteristics:          0x%04X\n",
           file_header.characteristics);


    /* ==============================
       STEP 4: READ OPTIONAL HEADER
       ============================== */

    size_t optional_size = file_header.sizeofoptionalheader;

    if (optional_size < 2) {
        printf("Error: Optional Header is too small\n");
        fclose(file);
        return 1;
    }

    // Allocate memory for the Optional Header
    uint8_t *optional_data = malloc(optional_size);

    if (optional_data == NULL) {
        perror("Memory allocation failed");
        fclose(file);
        return 1;
    }

    // Read the complete declared Optional Header
    if (fread(optional_data, 1, optional_size, file) != optional_size) {
        printf("Error: Could not read Optional Header\n");
        free(optional_data);
        fclose(file);
        return 1;
    }


    /* ==============================
       STEP 5: DETECT PE32 OR PE32+
       ============================== */

    uint16_t magic = read_u16(optional_data);

    uint64_t image_base;
    uint32_t number_of_directories;

    if (magic == 0x010B) {

        // PE32: 32-bit format
        if (optional_size < 0x60) {
            printf("Error: Incomplete PE32 Optional Header\n");
            free(optional_data);
            fclose(file);
            return 1;
        }

        image_base = read_u32(optional_data + 0x1C);

        number_of_directories =
            read_u32(optional_data + 0x5C);

    } else if (magic == 0x020B) {

        // PE32+: 64-bit format
        if (optional_size < 0x70) {
            printf("Error: Incomplete PE32+ Optional Header\n");
            free(optional_data);
            fclose(file);
            return 1;
        }

        image_base = read_u64(optional_data + 0x18);

        number_of_directories =
            read_u32(optional_data + 0x6C);

    } else {

        printf("Error: Unknown Optional Header format: 0x%04X\n",
               magic);

        free(optional_data);
        fclose(file);
        return 1;
    }


    /* ==============================
       STEP 6: READ OPTIONAL FIELDS
       ============================== */

    uint32_t entry_point =
        read_u32(optional_data + 0x10);

    uint32_t section_alignment =
        read_u32(optional_data + 0x20);

    uint32_t file_alignment =
        read_u32(optional_data + 0x24);

    uint32_t size_of_image =
        read_u32(optional_data + 0x38);

    uint32_t size_of_headers =
        read_u32(optional_data + 0x3C);

    uint16_t subsystem =
        read_u16(optional_data + 0x44);

    uint16_t dll_characteristics =
        read_u16(optional_data + 0x46);


    /* ==============================
       STEP 7: DISPLAY OPTIONAL HEADER
       ============================== */

    printf("\n========== OPTIONAL HEADER ==========\n");

    printf("Format:                   %s\n",
           magic == 0x020B ? "PE32+" : "PE32");

    printf("Magic:                    0x%04X\n", magic);

    printf("Entry Point RVA:          0x%08X\n",
           entry_point);

    printf("Image Base:               0x%016llX\n",
           (unsigned long long)image_base);

    printf("Section Alignment:        0x%08X\n",
           section_alignment);

    printf("File Alignment:           0x%08X\n",
           file_alignment);

    printf("Size of Image:            0x%08X\n",
           size_of_image);

    printf("Size of Headers:          0x%08X\n",
           size_of_headers);

    printf("Subsystem:                0x%04X\n",
           subsystem);

    printf("DLL Characteristics:      0x%04X\n",
           dll_characteristics);

    printf("Data Directory Count:     %u\n",
           number_of_directories);


    /* ==============================
       STEP 8: CHECK SECURITY FLAGS
       ============================== */
    // Identify whether the PE file is a DLL
    if (file_header.characteristics & 0x2000) {
        printf("File Type: DLL\n");
    }
    else if (file_header.characteristics & 0x0002) {
        printf("File Type: EXE / Executable Image\n");
    }
    else {
        printf("File Type: Other or unknown PE image\n");
    }
    printf("\n========== SECURITY FLAGS ==========\n");

    printf("High Entropy VA:          %s\n",
           (dll_characteristics & 0x0020)
           ? "Set" : "Not set");

    printf("Dynamic Base (ASLR):      %s\n",
           (dll_characteristics & 0x0040)
           ? "Set" : "Not set");

    printf("NX Compatible (DEP):      %s\n",
           (dll_characteristics & 0x0100)
           ? "Set" : "Not set");

    printf("Guard CF (CFG):           %s\n",
           (dll_characteristics & 0x4000)
           ? "Set" : "Not set");

    // Check whether the filename ends with .sys
    const char *extension = strrchr(argv[1], '.');
    
    int is_sys_file = (extension != NULL &&
                       strcasecmp(extension, ".sys") == 0);
    
    // Check driver-related PE header indicators
    int is_system_image =
        (file_header.characteristics & 0x1000) != 0;
    
    int is_native_subsystem =
        (subsystem == 1);
    
    int is_wdm_driver =
        (dll_characteristics & 0x2000) != 0;
    
    // Display results
    printf("\n========== SYS / DRIVER ANALYSIS ==========\n");
    
    
    printf("COFF System File Flag:       %s\n",
           is_system_image ? "Set" : "Not set");
    
    printf("Native Subsystem:            %s\n",
           is_native_subsystem ? "Yes" : "No");
    
    printf("WDM Driver Flag:             %s\n",
           is_wdm_driver ? "Set" : "Not set");
    
    if (is_system_image && is_native_subsystem) {
        printf("Assessment: Native system image; "
               "possible driver\n");
    }
    else if (is_sys_file) {
        printf("Assessment: .sys file; driver status "
               "needs further verification\n");
    }
    else {
        printf("Assessment: Not identified as a driver "
               "from these indicators\n");
    }
    /* ==============================
       STEP 9: CLEAN UP
       ============================== */

    free(optional_data);
    fclose(file);

    return 0;
}