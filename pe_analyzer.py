#!/usr/bin/env python3
import pefile
import argparse
import sys
import os
import math

def main():
    parser = argparse.ArgumentParser(description="PE file analysis and report generation")
    parser.add_argument("file", help="Path to the EXE file to analyze")
    args = parser.parse_args()

    if not os.path.exists(args.file):
        print("File not found: {}".format(args.file))
        sys.exit(1)

    try:
        pe = pefile.PE(args.file)
    except Exception as e:
        print("Error parsing file: {}".format(e))
        sys.exit(1)

    report = []
    report.append("PE Analysis Report for: {}\n".format(args.file))
    report.append("File Size: {} bytes".format(os.path.getsize(args.file)))
    report.append("-" * 60)

    # DOS Header
    report.append("\nDOS Header:")
    report.append("  e_magic: {}".format(pe.DOS_HEADER.e_magic))
    report.append("  e_lfanew (PE header offset): 0x{:X}".format(pe.DOS_HEADER.e_lfanew))

    # PE Header
    report.append("\nPE Header:")
    report.append("  Signature: {}".format(pe.NT_HEADERS.Signature))

    # COFF File Header
    report.append("\nCOFF File Header:")
    report.append("  Machine: 0x{:X}".format(pe.FILE_HEADER.Machine))
    report.append("  Number of Sections: {}".format(pe.FILE_HEADER.NumberOfSections))
    report.append("  TimeDateStamp: {}".format(pe.FILE_HEADER.TimeDateStamp))
    report.append("  PointerToSymbolTable: 0x{:X}".format(pe.FILE_HEADER.PointerToSymbolTable))
    report.append("  NumberOfSymbols: {}".format(pe.FILE_HEADER.NumberOfSymbols))
    report.append("  SizeOfOptionalHeader: {}".format(pe.FILE_HEADER.SizeOfOptionalHeader))
    report.append("  Characteristics: 0x{:X}".format(pe.FILE_HEADER.Characteristics))

    # Optional Header
    opt = pe.OPTIONAL_HEADER
    report.append("\nOptional Header:")
    report.append("  Magic: 0x{:X}".format(opt.Magic))
    report.append("  AddressOfEntryPoint: 0x{:X}".format(opt.AddressOfEntryPoint))
    report.append("  ImageBase: 0x{:X}".format(opt.ImageBase))
    report.append("  SectionAlignment: 0x{:X}".format(opt.SectionAlignment))
    report.append("  FileAlignment: 0x{:X}".format(opt.FileAlignment))
    report.append("  SizeOfImage: 0x{:X}".format(opt.SizeOfImage))
    report.append("  SizeOfHeaders: 0x{:X}".format(opt.SizeOfHeaders))

    # Data Directories
    report.append("\nData Directories:")
    for entry in opt.DATA_DIRECTORY:
        report.append("  {}: VirtualAddress=0x{:X}, Size=0x{:X}".format(entry.name, entry.VirtualAddress, entry.Size))

    # Sections
    report.append("\nSections:")
    for section in pe.sections:
        # Get entropy directly from the section
        entropy = section.get_entropy()
        section_name = section.Name.decode('utf-8', errors='replace').strip('\x00')
        report.append("  Name: {:8} | VA: 0x{:08X} | VirtualSize: 0x{:X} | RawSize: 0x{:X} | Entropy: {:.2f}".format(
            section_name,
            section.VirtualAddress,
            section.Misc_VirtualSize,
            section.SizeOfRawData,
            entropy
        ))

    # Imports
    report.append("\nImports:")
    if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            dll_name = entry.dll.decode('utf-8', errors='replace')
            report.append("  DLL: {}".format(dll_name))
            for imp in entry.imports:
                if imp.name:
                    func_name = imp.name.decode('utf-8', errors='replace')
                else:
                    func_name = "Ordinal {}".format(imp.ordinal)
                report.append("    {} at 0x{:08X}".format(func_name, imp.address))
    else:
        report.append("  No imports found.")

    # Exports
    report.append("\nExports:")
    if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
        for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
            if exp.name:
                exp_name = exp.name.decode('utf-8', errors='replace')
            else:
                exp_name = "Ordinal {}".format(exp.ordinal)
            report.append("  {} at 0x{:08X}".format(exp_name, pe.OPTIONAL_HEADER.ImageBase + exp.address))
    else:
        report.append("  No exports found.")

    # Debug information
    report.append("\nDebug Information:")
    if hasattr(pe, 'DIRECTORY_ENTRY_DEBUG'):
        for debug in pe.DIRECTORY_ENTRY_DEBUG:
            report.append("  Debug Type: 0x{:X}, Size: 0x{:X}".format(debug.struct.Type, debug.struct.SizeOfData))
    else:
        report.append("  No debug information found.")

    # Additional Analysis
    report.append("\nAdditional Analysis:")

    # 1. Check for high entropy sections (often a sign of packing or encryption)
    high_entropy_sections = []
    for section in pe.sections:
        if section.get_entropy() > 7.0:
            sec_name = section.Name.decode('utf-8', errors='replace').strip('\x00')
            high_entropy_sections.append(sec_name)
    if high_entropy_sections:
        report.append("  High entropy sections detected (possible packing/encryption): {}".format(
            ", ".join(high_entropy_sections)))
    else:
        report.append("  No suspicious high entropy sections detected.")

    # 2. Check if the entry point is located within a valid section
    entry_point = opt.AddressOfEntryPoint
    entry_section_found = False
    for section in pe.sections:
        start = section.VirtualAddress
        end = start + section.Misc_VirtualSize
        if start <= entry_point < end:
            sec_name = section.Name.decode('utf-8', errors='replace').strip('\x00')
            report.append("  Entry point 0x{:X} is located in section '{}'.".format(entry_point, sec_name))
            entry_section_found = True
            break
    if not entry_section_found:
        report.append("  Entry point 0x{:X} is not located within any section.".format(entry_point))

    # Combine and output the report
    final_report = "\n".join(report)
    print(final_report)

if __name__ == '__main__':
    main()
