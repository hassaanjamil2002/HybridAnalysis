import pefile
import os
import datetime
import math
import numpy as np  # Ensure numpy is imported

def calculate_entropy(data):
    if not data:
        return 0
    entropy = 0
    for x in range(256):
        p_x = float(data.count(bytes([x]))) / len(data)
        if p_x > 0:
            entropy += - p_x * math.log(p_x, 2)
    return entropy
def get_pe_info(pe_path):
    try:
        pe = pefile.PE(pe_path)
    except pefile.PEFormatError:
        print(f"Skipping non-PE file: {pe_path}")
        return None

    pe_info = {
        'file_name': os.path.basename(pe_path),
        'file_entropy': calculate_entropy(pe.sections[0].get_data()) if pe.sections else 0,
        'high_entropy_sections': sum(1 for section in pe.sections if calculate_entropy(section.get_data()) > 7) if pe.sections else 0,
        'repeated_section_names': len(pe.sections) - len(set(section.Name.decode().rstrip('\x00') for section in pe.sections)) if pe.sections else 0,
        'non_standard_section_names': sum(1 for section in pe.sections if not section.Name.decode().rstrip('\x00').startswith('.')) if pe.sections else 0,
        'zero_raw_size_sections': sum(1 for section in pe.sections if section.SizeOfRawData == 0) if pe.sections else 0,
        'sum_section_sizes_greater': 1 if pe.sections and sum(section.Misc_VirtualSize for section in pe.sections) > pe.OPTIONAL_HEADER.SizeOfImage else 0,
        'section_alignment': pe.OPTIONAL_HEADER.SectionAlignment,
        'file_alignment': pe.OPTIONAL_HEADER.FileAlignment,
        'pe_resource_count': len(pe.DIRECTORY_ENTRY_RESOURCE.entries) if hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE') else 0,
        'no_image_version': 1 if not hasattr(pe, 'VS_VERSIONINFO') else 0,
        'malicious_import_functions': sum(1 for entry in pe.DIRECTORY_ENTRY_IMPORT if any(func.name.startswith(b'LoadLibrary') for func in entry.imports if func.name is not None)),
        'imports_related_to_packing': sum(1 for entry in pe.DIRECTORY_ENTRY_IMPORT if any(func.name in (b'GetProcAddress', b'LoadLibrary') for func in entry.imports if func.name is not None)),
        'invalid_compile_time': 1 if datetime.datetime.utcfromtimestamp(pe.FILE_HEADER.TimeDateStamp).year < 1980 else 0
    }   
    return pe_info


def analyze_pe_files_in_directory(directory):
    pe_infos = []
    for root, dirs, files in os.walk(directory):
        for file in files:
            file_path = os.path.join(root, file)
            info = get_pe_info(file_path)
            if info:
                pe_infos.append(info)
    return pe_infos

# Example usage
directory_path = r"C:\Users\Faheem\Downloads\ProjectVARE"
pe_data = analyze_pe_files_in_directory(directory_path)
for info in pe_data:
    print(info)
