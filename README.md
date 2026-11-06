# MZScope

**A lightweight Portable Executable (PE) header inspection tool written in C.**

MZScope reads selected metadata from Windows PE files and reports useful header characteristics, including PE32/PE32+ format information, executable and DLL indicators, and selected security-related flags.

It is also available as a browser-based WebAssembly build. You can inspect a supported file directly in your browser without uploading it to a server.

<p align="center">
  <a href="https://hritom.vercel.app/tools/parser/">Try MZScope in your browser</a>
</p>

## Features

- **Header validation**
  - Checks the DOS `MZ` signature.
  - Uses `e_lfanew` to locate the PE header.
  - Validates the `PE\0\0` signature.
- **COFF File Header inspection**
  - Machine architecture value
  - Number of sections
  - Time/date stamp
  - Symbol-table pointer and symbol count
  - Optional Header size
  - COFF characteristics
- **PE format detection**
  - PE32 (`0x010B`)
  - PE32+ (`0x020B`)
- **Optional Header inspection**
  - Entry Point RVA
  - Image Base
  - Section and file alignment
  - Size of image and headers
  - Subsystem
  - Number of data directories
- **Security-related flag checks**
  - High Entropy VA
  - Dynamic Base (ASLR)
  - NX Compatible (DEP)
  - Guard CF (CFG)
- **Basic image and driver indicators**
  - Reports EXE/DLL-related COFF characteristics.
  - Displays the COFF System File characteristic, Native subsystem indicator, and WDM Driver flag.
  - Uses the `.sys` extension as an additional hint, not as proof of driver status.

## Online version

**Web interface:** <https://hritom.vercel.app/tools/parser/>

The website describes this as a WebAssembly port of `parser.c`. It accepts `.exe`, `.dll`, and `.sys` files through file selection or drag and drop. The page states that parsing takes place in the browser and that the file is not uploaded.

## Build from source

### Requirements

- GCC or a compatible C compiler
- A POSIX-like environment (the current source uses `strcasecmp()` from `<strings.h>`)

### Compile

Clone the repository and build the parser:

```bash
git clone https://github.com/Shadow-Spinner/mzscope.git
cd mzscope
gcc -Wall -Wextra -std=c11 parser.c -o mzscope
```

> Replace the repository URL above if you publish the project under a different GitHub account or repository name.

## Usage

Pass the path to a PE file as the only command-line argument:

```bash
./mzscope /path/to/file.exe
```

Examples:

```bash
./mzscope sample.exe
./mzscope library.dll
./mzscope driver.sys
```

MZScope prints the parsed header values and the selected characteristic checks to the terminal. If the file cannot be opened, a required header cannot be read, or a signature/format check fails, the program reports an error and exits with a non-zero status.

## What the parser checks

At a high level, the current implementation follows this sequence:

1. Opens the input file in binary-read mode.
2. Reads the DOS header and verifies the `MZ` signature.
3. Seeks to the PE header using the DOS header's `e_lfanew` field and verifies the `PE\0\0` signature.
4. Reads and displays selected COFF File Header fields.
5. Reads the Optional Header using the size declared in the COFF header.
6. Checks the Optional Header magic to distinguish PE32 from PE32+.
7. Extracts selected Optional Header fields using their format-specific offsets.
8. Checks selected DLL Characteristics and COFF characteristic bits, then displays the results.

## Understanding the security flags

The parser reports whether the corresponding bits are set in the PE Optional Header's DLL Characteristics field.

| Flag | What the header bit indicates |
|---|---|
| High Entropy VA | The image declares support for high-entropy 64-bit address randomization. |
| Dynamic Base (ASLR) | The image declares that it can be rebased for address-space layout randomization. |
| NX Compatible (DEP) | The image declares compatibility with hardware-enforced data execution prevention. |
| Guard CF (CFG) | The image declares Control Flow Guard support. |

These are header-level indicators only. A flag being present does not, by itself, prove that a mitigation is effective in every runtime context.

## Scope and limitations

MZScope is currently a **focused PE header inspection tool**, not a complete PE/COFF parser, malware scanner, or driver-validation utility.

- It reports the section count but does not parse individual section headers or section contents.
- It reports the data-directory count but does not decode the individual data-directory entries.
- It does not currently inspect imports, exports, resources, relocations, debug information, Authenticode signatures, or overlay data.
- Driver-related output is heuristic. A `.sys` filename, the COFF System File characteristic, the Native subsystem, and the WDM Driver flag are indicators; they do not independently prove that a file is a valid, loadable, or safe driver.
- Security flags reflect values declared in the file headers. They are not a runtime security assessment.
- The implementation performs basic structural checks, but it should not be considered hardened against every malformed or adversarial input file.

Use the tool for learning and preliminary inspection. Do not rely on it as the sole basis for malware classification, driver trust decisions, or security assurance.

## Project structure

```text
mzscope/
├── parser.c
└── README.md
```

## License

No license has been added yet. Until a license is included in the repository, the usual default copyright restrictions apply. Add a license file before granting others explicit permission to reuse, modify, or distribute the code.
