import sys
import json
import struct
from pathlib import Path
from typing import List, Dict, Optional
from collections import Counter

try:
    import pefile
except ImportError:
    print(" Erro: pefile não instalado")
    print("   Instale com: pip install pefile")
    sys.exit(1)


                                         
SUSPICIOUS_APIS = {
    'VirtualAlloc', 'VirtualAllocEx', 'VirtualProtect', 'VirtualProtectEx',
    'CreateRemoteThread', 'CreateThread', 'WriteProcessMemory', 'ReadProcessMemory',
    'OpenProcess', 'TerminateProcess', 'GetProcAddress', 'LoadLibrary',
    'WinExec', 'ShellExecute', 'CreateProcess', 'ResumeThread',
    'SetWindowsHookEx', 'GetAsyncKeyState', 'GetForegroundWindow',
    'InternetOpen', 'InternetConnect', 'HttpSendRequest', 'URLDownloadToFile',
    'RegCreateKey', 'RegSetValue', 'RegOpenKey', 'RegDeleteKey',
    'CryptEncrypt', 'CryptDecrypt', 'CryptCreateHash'
}

                                                  
SUSPICIOUS_SECTION_NAMES = {
    '.UPX', 'UPX0', 'UPX1', 'UPX2',
    '.ASPack', '.RLPack', '.MPRESS', '.Themida',
    '.packed', '.enigma', '.vmp', '.obsidium'
}


def extract_pe_features(file_path: str) -> List[float]:
    try:
        pe = pefile.PE(file_path)
    except Exception as e:
        raise ValueError(f"Erro ao parsear PE: {e}")
    
    features = []
    
                                                                        
    features.append(pe.DOS_HEADER.e_magic)
    features.append(pe.DOS_HEADER.e_cblp)
    features.append(pe.DOS_HEADER.e_cp)
    features.append(pe.DOS_HEADER.e_crlc)
    features.append(pe.DOS_HEADER.e_cparhdr)
    features.append(pe.DOS_HEADER.e_minalloc)
    features.append(pe.DOS_HEADER.e_maxalloc)
    features.append(pe.DOS_HEADER.e_ss)
    features.append(pe.DOS_HEADER.e_sp)
    features.append(pe.DOS_HEADER.e_csum)
    features.append(pe.DOS_HEADER.e_ip)
    features.append(pe.DOS_HEADER.e_cs)
    features.append(pe.DOS_HEADER.e_lfarlc)
    features.append(pe.DOS_HEADER.e_ovno)
    features.append(pe.DOS_HEADER.e_oemid)
    features.append(pe.DOS_HEADER.e_oeminfo)
    features.append(pe.DOS_HEADER.e_lfanew)
    
                                                                        
    features.append(pe.FILE_HEADER.Machine)
    features.append(pe.FILE_HEADER.NumberOfSections)
    features.append(pe.FILE_HEADER.TimeDateStamp)
    features.append(pe.FILE_HEADER.PointerToSymbolTable)
    features.append(pe.FILE_HEADER.NumberOfSymbols)
    features.append(pe.FILE_HEADER.SizeOfOptionalHeader)
    features.append(pe.FILE_HEADER.Characteristics)
    
                                                                             
    features.append(pe.OPTIONAL_HEADER.Magic)
    features.append(pe.OPTIONAL_HEADER.MajorLinkerVersion)
    features.append(pe.OPTIONAL_HEADER.MinorLinkerVersion)
    features.append(pe.OPTIONAL_HEADER.SizeOfCode)
    features.append(pe.OPTIONAL_HEADER.SizeOfInitializedData)
    features.append(pe.OPTIONAL_HEADER.SizeOfUninitializedData)
    features.append(pe.OPTIONAL_HEADER.AddressOfEntryPoint)
    features.append(pe.OPTIONAL_HEADER.BaseOfCode)
    features.append(pe.OPTIONAL_HEADER.ImageBase)
    features.append(pe.OPTIONAL_HEADER.SectionAlignment)
    features.append(pe.OPTIONAL_HEADER.FileAlignment)
    features.append(pe.OPTIONAL_HEADER.MajorOperatingSystemVersion)
    features.append(pe.OPTIONAL_HEADER.MinorOperatingSystemVersion)
    features.append(pe.OPTIONAL_HEADER.MajorImageVersion)
    features.append(pe.OPTIONAL_HEADER.MinorImageVersion)
    features.append(pe.OPTIONAL_HEADER.MajorSubsystemVersion)
    features.append(pe.OPTIONAL_HEADER.MinorSubsystemVersion)
    features.append(pe.OPTIONAL_HEADER.SizeOfHeaders)
    features.append(pe.OPTIONAL_HEADER.CheckSum)
    features.append(pe.OPTIONAL_HEADER.SizeOfImage)
    features.append(pe.OPTIONAL_HEADER.Subsystem)
    features.append(pe.OPTIONAL_HEADER.DllCharacteristics)
    features.append(pe.OPTIONAL_HEADER.SizeOfStackReserve)
    features.append(pe.OPTIONAL_HEADER.SizeOfStackCommit)
    features.append(pe.OPTIONAL_HEADER.SizeOfHeapReserve)
    features.append(pe.OPTIONAL_HEADER.SizeOfHeapCommit)
    features.append(pe.OPTIONAL_HEADER.LoaderFlags)
    features.append(pe.OPTIONAL_HEADER.NumberOfRvaAndSizes)
    
                                                                                 
                                                                                
    features.append(0)
    
                                                                                
    suspicious_imports = count_suspicious_imports(pe)
    suspicious_sections = count_suspicious_sections(pe)
    features.append(suspicious_imports)
    features.append(suspicious_sections)
    
                                                                                
    section_stats = calculate_section_stats(pe)
    features.append(section_stats['SectionsLength'])
    features.append(section_stats['SectionMinEntropy'])
    features.append(section_stats['SectionMaxEntropy'])
    features.append(section_stats['SectionMinRawsize'])
    features.append(section_stats['SectionMaxRawsize'])
    features.append(section_stats['SectionMinVirtualsize'])
    features.append(section_stats['SectionMaxVirtualsize'])
    features.append(section_stats['SectionMaxPhysical'])
    features.append(section_stats['SectionMinPhysical'])
    features.append(section_stats['SectionMaxVirtual'])
    features.append(section_stats['SectionMinVirtual'])
    features.append(section_stats['SectionMaxPointerData'])
    features.append(section_stats['SectionMinPointerData'])
    features.append(section_stats['SectionMaxChar'])
    features.append(section_stats['SectionMainChar'])
    
                                                                              
    features.append(section_stats['DirectoryEntryImport'])
    features.append(section_stats['DirectoryEntryImportSize'])
    features.append(section_stats['DirectoryEntryExport'])
    features.append(section_stats['ImageDirectoryEntryExport'])
    features.append(section_stats['ImageDirectoryEntryImport'])
    features.append(section_stats['ImageDirectoryEntryResource'])
    features.append(section_stats['ImageDirectoryEntryException'])
    features.append(section_stats['ImageDirectoryEntrySecurity'])
    
    return features


def count_suspicious_imports(pe: pefile.PE) -> int:
    count = 0
    
    if not hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
        return 0
    
    for entry in pe.DIRECTORY_ENTRY_IMPORT:
        for imp in entry.imports:
            if imp.name and imp.name.decode('utf-8', errors='ignore') in SUSPICIOUS_APIS:
                count += 1
    
    return count


def count_suspicious_sections(pe: pefile.PE) -> int:
    count = 0
    
    for section in pe.sections:
        name = section.Name.decode('utf-8', errors='ignore').strip('\x00')
        if any(susp in name for susp in SUSPICIOUS_SECTION_NAMES):
            count += 1
    
    return count


def calculate_section_stats(pe: pefile.PE) -> Dict[str, float]:
    if not pe.sections:
        return {
            'SectionsLength': 0,
            'SectionMinEntropy': 0.0,
            'SectionMaxEntropy': 0.0,
            'SectionMinRawsize': 0,
            'SectionMaxRawsize': 0,
            'SectionMinVirtualsize': 0,
            'SectionMaxVirtualsize': 0,
            'SectionMaxPhysical': 0,
            'SectionMinPhysical': 0,
            'SectionMaxVirtual': 0,
            'SectionMinVirtual': 0,
            'SectionMaxPointerData': 0,
            'SectionMinPointerData': 0,
            'SectionMaxChar': 0,
            'SectionMainChar': 0,
            'DirectoryEntryImport': 0,
            'DirectoryEntryImportSize': 0,
            'DirectoryEntryExport': 0,
            'ImageDirectoryEntryExport': 0,
            'ImageDirectoryEntryImport': 0,
            'ImageDirectoryEntryResource': 0,
            'ImageDirectoryEntryException': 0,
            'ImageDirectoryEntrySecurity': 0
        }
    
    entropies = [section.get_entropy() for section in pe.sections]
    raw_sizes = [section.SizeOfRawData for section in pe.sections]
    virtual_sizes = [section.Misc_VirtualSize for section in pe.sections]
    characteristics = [section.Characteristics for section in pe.sections]
    pointer_data = [section.PointerToRawData for section in pe.sections]
    
                       
    dir_import = 0
    dir_import_size = 0
    dir_export = 0
    
    if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
        dir_import = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_IMPORT']].VirtualAddress
        dir_import_size = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_IMPORT']].Size
    
    if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
        dir_export = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_EXPORT']].VirtualAddress
    
    stats = {
        'SectionsLength': len(pe.sections),
        'SectionMinEntropy': min(entropies) if entropies else 0.0,
        'SectionMaxEntropy': max(entropies) if entropies else 0.0,
        'SectionMinRawsize': min(raw_sizes) if raw_sizes else 0,
        'SectionMaxRawsize': max(raw_sizes) if raw_sizes else 0,
        'SectionMinVirtualsize': min(virtual_sizes) if virtual_sizes else 0,
        'SectionMaxVirtualsize': max(virtual_sizes) if virtual_sizes else 0,
        'SectionMaxPhysical': max(raw_sizes) if raw_sizes else 0,
        'SectionMinPhysical': min(raw_sizes) if raw_sizes else 0,
        'SectionMaxVirtual': max(virtual_sizes) if virtual_sizes else 0,
        'SectionMinVirtual': min(virtual_sizes) if virtual_sizes else 0,
        'SectionMaxPointerData': max(pointer_data) if pointer_data else 0,
        'SectionMinPointerData': min(pointer_data) if pointer_data else 0,
        'SectionMaxChar': max(characteristics) if characteristics else 0,
        'SectionMainChar': characteristics[0] if characteristics else 0,
        'DirectoryEntryImport': dir_import,
        'DirectoryEntryImportSize': dir_import_size,
        'DirectoryEntryExport': dir_export,
        'ImageDirectoryEntryExport': pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_EXPORT']].VirtualAddress,
        'ImageDirectoryEntryImport': pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_IMPORT']].VirtualAddress,
        'ImageDirectoryEntryResource': pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_RESOURCE']].VirtualAddress,
        'ImageDirectoryEntryException': pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_EXCEPTION']].VirtualAddress,
        'ImageDirectoryEntrySecurity': pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_SECURITY']].VirtualAddress
    }
    
    return stats


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)
    
    file_path = sys.argv[1]
    output_json = '--json' in sys.argv
    
    if not Path(file_path).exists():
        print(f" Ficheiro não encontrado: {file_path}")
        sys.exit(1)
    
    try:
        features = extract_pe_features(file_path)
        
        if output_json:
                         
            df = pd.read_csv('Data/dataset_malwares_balanced.csv')
            feature_names = df.drop(columns=['Name']).columns.tolist()
            
            feature_dict = {name: val for name, val in zip(feature_names, features)}
            print(json.dumps(feature_dict, indent=2))
        else:
                                 
            print(f"# Features extraídas: {len(features)}")
            print(f"features = {features}")
            
    except Exception as e:
        print(f" Erro: {e}")
        sys.exit(1)


if __name__ == '__main__':
    main()
