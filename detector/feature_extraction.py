import pefile
import lief
import os
import math
import re
import string
from collections import Counter

def get_entropy(data):
    if not data:
        return 0.0
    entropy = 0
    for x in range(256):
        p_x = data.count(bytes([x])) / len(data)
        if p_x > 0:
            entropy -= p_x * math.log2(p_x)
    return entropy

def extract_strings(data, min_len=4):
    pattern = rb'[\x20-\x7E]{%d,}' % min_len
    return re.findall(pattern, data)

def is_printable(s):
    return all(chr(c) in string.printable for c in s)

def average_string_length(strings):
    if not strings:
        return 0
    return sum(len(s) for s in strings) / len(strings)

def extract_pe_features(file_path):
    try:
        pe = pefile.PE(file_path)
        lief_pe = lief.parse(file_path)
        data = open(file_path, 'rb').read()
        strings = extract_strings(data)
        features = {}
        opt = pe.OPTIONAL_HEADER
        features['numstrings'] = len(strings)
        features['avlength'] = average_string_length(strings)
        features['printables'] = sum([1 for s in strings if is_printable(s)])
        features['entropy'] = get_entropy(data)
        features['MZ'] = int(data[:2] == b'MZ')
        features['size'] = os.path.getsize(file_path)
        features['vsize'] = opt.SizeOfImage
        features['has_debug'] = int(hasattr(pe, 'DIRECTORY_ENTRY_DEBUG'))
        features['exports_counts'] = len(pe.DIRECTORY_ENTRY_EXPORT.symbols) if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT') else 0
        features['imports_counts'] = len(pe.DIRECTORY_ENTRY_IMPORT) if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT') else 0
        features['has_relocations'] = int(hasattr(pe, 'DIRECTORY_ENTRY_BASERELOC'))
        features['has_resources'] = int(hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'))
        features['has_signature'] = int(hasattr(pe, 'DIRECTORY_ENTRY_SECURITY'))
        features['has_tls'] = int(hasattr(pe, 'DIRECTORY_ENTRY_TLS'))
        features['symbols'] = len(lief_pe.symbols) if lief_pe and lief_pe.symbols else 0
        features['coff.timestamp'] = pe.FILE_HEADER.TimeDateStamp
        features['optional.major_image_version'] = opt.MajorImageVersion
        features['optional.minor_image_version'] = opt.MinorImageVersion
        features['optional.major_linker_version'] = opt.MajorLinkerVersion
        features['optional.minor_linker_version'] = opt.MinorLinkerVersion
        features['optional.major_operating_system_version'] = opt.MajorOperatingSystemVersion
        features['optional.minor_operating_system_version'] = opt.MinorOperatingSystemVersion
        features['optional.major_subsystem_version'] = opt.MajorSubsystemVersion
        features['optional.minor_subsystem_version'] = opt.MinorSubsystemVersion
        features['optional.sizeof_code'] = opt.SizeOfCode
        features['optional.sizeof_headers'] = opt.SizeOfHeaders
        features['optional.sizeof_heap_commit'] = opt.SizeOfHeapCommit
        return features
    except Exception as e:
        print(f"Error processing {file_path}: {str(e)}")
        return None