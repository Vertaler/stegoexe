import lief
import math
import os
from itertools import chain
from conversions import int_to_bytelist, bytelist_to_int

IMPORT_DESCRIPTOR_SIZE = 20
IMPORT_NAME_OFFSET = 12
IMPORT_FIRST_THUNK_OFFSET = 16
IMPORT_ORIG_FIRST_THUNK_OFFSET = 0


def get_relocs_va(binary):
    for entry in chain(*[reloc.entries for reloc in binary.relocations]):
        if entry.type == lief.PE.RELOCATIONS_BASE_TYPES.ABSOLUTE:
            continue
        yield entry.address


def read_dword(binary, address):
    byte_list = binary.get_content_from_virtual_address(address, 4)
    res = 0
    for i, val in enumerate(byte_list):
        res += (256 ** i) * val
    return res


def patch_dword(binary, addr, value):
    patch_list = [0xFF & (value >> (8 * (3 - i))) for i in range(4)]
    binary.patch_address(address=addr, patch_value=patch_list)


def fix_import_functions(binary, raw_binary, first_thunk_rva, start_value, fix):
    func_address_offset = binary.rva_to_offset(first_thunk_rva)
    current_func_address = bytelist_to_int(raw_binary[func_address_offset:][:4])
    if first_thunk_rva == 0:
        return
    while current_func_address != 0:
        if current_func_address >= start_value:
            current_func_address += fix
            raw_binary[func_address_offset:func_address_offset + 4] = int_to_bytelist(current_func_address)
            print "first_thunk: {:08x}, offset: {:08x} func address: {:08x}".format(first_thunk_rva,
                                                                                    func_address_offset,
                                                                                    current_func_address)
        func_address_offset += 4
        current_func_address = bytelist_to_int(raw_binary[func_address_offset:][:4])


def fix_import(binary, start_value, fix):
    tmp_name = binary.name + ".tmp"
    binary.write(tmp_name)
    with open(tmp_name, 'rb') as raw_binary:
        binary_raw_data = raw_binary.read()
        binary_raw_data = map(ord, binary_raw_data)
        import_directory = binary.data_directory(lief.PE.DATA_DIRECTORY.IMPORT_TABLE)
        descriptors_count = import_directory.size / IMPORT_DESCRIPTOR_SIZE
        imports_offset = binary.rva_to_offset(import_directory.rva)

        for i in range(descriptors_count):
            descriptor_offset = imports_offset + IMPORT_DESCRIPTOR_SIZE * i
            name_address_offset = descriptor_offset + IMPORT_NAME_OFFSET
            name_address = bytelist_to_int(binary_raw_data[name_address_offset:][:4])
            if name_address >= start_value:
                name_address += fix
            binary_raw_data[name_address_offset: name_address_offset + 4] = int_to_bytelist(name_address)

            ft_offset = descriptor_offset + IMPORT_FIRST_THUNK_OFFSET
            ft_rva = bytelist_to_int(binary_raw_data[ft_offset:][:4])
            if ft_rva >= start_value:
                ft_rva += fix
            binary_raw_data[ft_offset:ft_offset + 4] = int_to_bytelist(ft_rva)

            oft_offset = descriptor_offset + IMPORT_ORIG_FIRST_THUNK_OFFSET
            oft_rva = bytelist_to_int(binary_raw_data[oft_offset:][:4])
            fix_import_functions(binary, binary_raw_data, oft_rva, start_value, fix)
            if oft_rva >= start_value:
                oft_rva += fix
            binary_raw_data[oft_offset:oft_offset + 4] = int_to_bytelist(oft_rva)

    os.remove(tmp_name)
    new_binary = lief.PE.parse(binary_raw_data)
    return new_binary


def fix_refs(binary, start_value, fix):
    imagebase = binary.optional_header.imagebase
    for reloc_va in get_relocs_va(binary):
        dword = read_dword(binary, reloc_va) - imagebase
        if dword >= start_value:
            patch_dword(binary, reloc_va, dword + fix)


def fix_datadirectories(binary, start_value, fix):
    for data_dir in binary.data_directories:
        if data_dir.rva >= start_value:
            data_dir.rva += fix


def expand_section(binary, section_name, raw_expansion):
    found = False
    raw_size_addition = binary.optional_header.file_alignment * raw_expansion
    section_alignment = binary.optional_header.section_alignment
    virtual_size_addition = int (math.ceil(float(raw_size_addition) / section_alignment)) * section_alignment

    section = binary.get_section(section_name)
    index = list(binary.sections).index(section)

    if index < len(binary.sections) - 1:
        start_value_for_fixes = binary.sections[index + 1].virtual_address
        binary = fix_import(binary, start_value_for_fixes, virtual_size_addition)
        fix_datadirectories(binary, start_value_for_fixes, virtual_size_addition)
        section = binary.get_section(section_name)
    section.size += raw_size_addition
    section.virtual_size += virtual_size_addition

    for other_section in list(binary.sections)[index + 1:]:
        other_section.offset += raw_size_addition
        other_section.virtual_address += virtual_size_addition

    return binary


def light_expand_section(binary, section_name):
    section = binary.get_section(section_name)
    section_alignment = binary.optional_header.section_alignment
    new_size = int(math.ceil(float(section.size) / section_alignment)) * section_alignment
    size_delta = new_size - section.size
    section.size = new_size
    section_index = list(binary.sections).index(section)
    for following_section in list(binary.sections)[section_index + 1:]:
        following_section.offset += size_delta


def rebuild_binary(binary, output_path):
    new_binary = lief.PE.Binary(binary.name, lief.PE.PE_TYPE.PE32)
    new_binary.dos_header.addressof_new_exeheader = binary.dos_header.addressof_new_exeheader
    new_binary.dos_stub = binary.dos_stub
    new_binary.optional_header.subsystem = binary.optional_header.subsystem
    for section in binary.sections:
        if len(section.content) < section.size:
            section.content += [0] * (section.size - len(section.content))
        new_binary.add_section(section)
    for dir1, dir2 in zip(new_binary.data_directories, binary.data_directories):
        dir1.rva = dir2.rva
        dir1.size = dir2.size
    new_binary.optional_header.addressof_entrypoint = binary.optional_header.addressof_entrypoint

    new_binary.write(output_path)
