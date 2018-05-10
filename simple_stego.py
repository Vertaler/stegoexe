from asm_utils import asm, Disasassembler
from conversions import bites_to_str, str_to_bites, is_int
import lief

END_OF_MESSAGE = '\x00'


def is_instr_suitable_for_stego(instr):
    '''
    :param instr: assembler instruction
    :type instr: (capstone.CsInsn)
    :rtype: bool
    :return: True if instr is 'sub' or 'add' and it has number second operand, False otherwise
    For example,
    add eax, 1 -> True
    add eax, ebx -> False (second operand is not number)
    adc eax, 1 -> False (instruction is not add or sub)
    '''
    if instr.mnemonic not in ["sub", "add"]:
        return False
    sec_oper = instr.op_str.split(', ')[1]
    return is_int(sec_oper, 16)


def get_suitable_for_stego_instructions(code):
    disas = Disasassembler(offset=0)
    return [instr for instr in disas.disasm(code) if is_instr_suitable_for_stego(instr)]


def insert_single_bit(bit, instr, code):
    substitution_dict = {
        'add': 'sub',
        'sub': 'add'
    }

    if bit not in '01':
        raise ValueError("Inserting bit must be '0' or '1', not {}".format(bit))

    if bit == '0' and instr.mnemonic == 'add' or bit == '1' and instr.mnemonic == 'sub':
        return
    else:
        first_oper, sec_oper = instr.op_str.split(', ')
        sec_oper = str(-int(sec_oper, 16))
        new_instr = substitution_dict[instr.mnemonic] + ' ' + first_oper + ', ' + sec_oper
        asm_new_instr = asm(new_instr)
        code[instr.address:instr.address + len(instr.bytes)] = map(ord, asm_new_instr)


def extract_single_bit(instr):
    if instr.mnemonic == 'add':
        return '0'
    elif instr.mnemonic == 'sub':
        return '1'
    else:
        raise ValueError("instr.mnemonic must be '0' or '1'")


def insert_message(message, binary_path, output_path):
    binary = lief.PE.parse(binary_path)
    entrypoint = binary.optional_header.addressof_entrypoint
    code_section = binary.section_from_rva(entrypoint)
    code = code_section.content
    str_code = ''.join(map(chr, code))
    suitable_instrs = get_suitable_for_stego_instructions(str_code)
    suitable_instrs_iter = iter(suitable_instrs)
    if len(message + END_OF_MESSAGE) >= len(suitable_instrs) / 8:
        print "Can not insert message '{0}' in {1}, because {1} " \
              "has not enough add, sub instructions".format(message,binary_path)
        return
    for bit in str_to_bites(message + END_OF_MESSAGE):
        instr = suitable_instrs_iter.next()
        insert_single_bit(bit, instr, code)

    code_section.content = code
    binary.write(output_path)


def extract_message(binary_path):
    binary = lief.PE.parse(binary_path)
    entrypoint = binary.optional_header.addressof_entrypoint
    code_section = binary.section_from_rva(entrypoint)
    code = ''.join(map(chr, code_section.content))
    suitable_instrs = get_suitable_for_stego_instructions(code)
    extracted_bits = ''
    for instr in suitable_instrs:
        extracted_bits += extract_single_bit(instr)

    # remove last bits, make length of list is divided by 8
    extracted_bits = extracted_bits[:len(extracted_bits) & ~7]

    message = bites_to_str(extracted_bits)
    if END_OF_MESSAGE not in message:
        print 'Can not extract message, END_OF_MESSAGE not found'
        return None

    message = message.split(END_OF_MESSAGE)[0]
    return message
