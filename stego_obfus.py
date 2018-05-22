from hashlib import md5
import re

import lief

from random_nop import random_nop
from asm_utils import Disasassembler, asm
from binary_utils import light_expand_section, rebuild_binary

BLOCK_SIZE = 32
MINIMAL_SIZE_FOR_STEGO = 14
JMP_INSTR_REGEX = re.compile('^((rep|repn|repe)\s)?j.*')
END_OF_MESSAGE = '\x00'


def hash_code(block, length=1):
    return md5(block).digest()[0:length]

def is_jmp(instr):
    return  JMP_INSTR_REGEX.match(instr.mnemonic)


def jmp_asm(address):
    return asm("jmp {}".format(address))


def fix_jumps(block, initial_position, next_position):
    res = ''
    jmp_dict_operands = {}
    prev_jmp_list = []
    disas = Disasassembler(offset=0)
    instr_list = list(disas.disasm(str(block)))
    jmp_iter = (instr for instr in instr_list if instr.mnemonic[0] == 'j')

    def update_previous_jumps(start_address, fix):
        for prev_jmp in prev_jmp_list:
            if jmp_dict_operands[prev_jmp.address] >= start_address - prev_jmp.address:
                jmp_dict_operands[prev_jmp.address] += fix

    for instr in jmp_iter:
        jmp_operand = int(instr.op_str, 16) - instr.address
        if jmp_operand + instr.address >= len(block) or (jmp_operand + instr.address) < 0:
            jmp_operand -= (next_position - initial_position)
            asm_instr = asm(instr.mnemonic + ' ' + str(jmp_operand))
            if len(asm_instr) > len(instr.bytes):
                update_previous_jumps(instr.address, len(asm_instr) - len(instr.bytes))
        jmp_dict_operands[instr.address] = jmp_operand
        prev_jmp_list.append(instr)

    for instr in instr_list:
        if instr.address in jmp_dict_operands:
            str_operand = str(jmp_dict_operands[instr.address])
            res += asm(instr.mnemonic + ' ' + str_operand)
        else:
            res += str(instr.bytes)
    return res


def has_xref(address, instrs):
    for instr in instrs:
        try:
            if int(instr.op_str, 16) == address:
                return True
        except ValueError:
            continue
    return False


def insert_char(char, head, tail):
    nops_size = BLOCK_SIZE - len(head) - len(tail)
    print "expected {}, real {}".format(nops_size, len((random_nop(nops_size))))

    block = head + random_nop(nops_size) + tail
    while hash_code(block) != char:
        block = head + random_nop(nops_size) + tail
    return block


def insert_message(message, binary_path):
    binary = lief.parse(binary_path)
    entrypoint = binary.optional_header.addressof_entrypoint
    code_section = binary.section_from_rva(entrypoint)
    code = "".join(map(chr, code_section.content))
    disas = Disasassembler(offset=0)
    disas_iter = iter(disas.disasm(code))
    current_block = ''
    head_len = len(current_block)
    message += END_OF_MESSAGE
    instrs_to_find_xrefs = [instr for instr in disas.disasm(code) if is_jmp(instr)]

    light_expand_section(binary, code_section.name)

    for i, ch in enumerate(message):
        instr = disas_iter.next()
        xref_find = False
        tail_len = 0
        while len(current_block + str(instr.bytes)) <= BLOCK_SIZE:
            current_block += str(instr.bytes)

            if not xref_find and (has_xref(instr.address, instrs_to_find_xrefs) or instr.mnemonic =='ret'):
                if len(current_block)-head_len >= MINIMAL_SIZE_FOR_STEGO:
                    xref_find = True
                    tail_len = BLOCK_SIZE - len(current_block) #- len(instr.bytes)
                else:
                    head_len = len(current_block)

            print instr.mnemonic + " " + instr.op_str
            instr = disas_iter.next()

        last_instr_head_len = BLOCK_SIZE - len(current_block)
        current_block += str(instr.bytes)[:last_instr_head_len]
        if tail_len == 0:
            tail_len = last_instr_head_len

        instructions_to_move = current_block[head_len: BLOCK_SIZE - tail_len]
        instructions_to_move = fix_jumps(instructions_to_move, i * BLOCK_SIZE + head_len, len(code))
        instructions_to_move += jmp_asm(instr.address - len(code) - len(instructions_to_move))

        new_block_head = current_block[:head_len] + jmp_asm(len(code) - BLOCK_SIZE * i - head_len)
        new_block_tail = current_block[BLOCK_SIZE - tail_len:]
        new_block = insert_char(ch, new_block_head, new_block_tail)
        print len(new_block)
        code = code[:i * BLOCK_SIZE] + new_block + code[(i + 1) * BLOCK_SIZE:] + instructions_to_move

        current_block = instr.bytes[last_instr_head_len:]
        head_len = len(current_block)

    new_code = map(ord, str(code))
    code_section.content = new_code
    binary.optional_header.dll_characteristics &= ~lief.PE.DLL_CHARACTERISTICS.DYNAMIC_BASE
    rebuild_binary(binary, "modified.exe")


def extract_message(binary_path):
    binary = lief.parse(binary_path)
    entrypoint = binary.optional_header.addressof_entrypoint
    code_section = binary.section_from_rva(entrypoint)
    code = "".join(map(chr, code_section.content))
    message = ''
    for i in range(0, len(code), BLOCK_SIZE):
        message += hash_code(code[i:i + BLOCK_SIZE])

    if END_OF_MESSAGE not in message:
        print 'Can not extract message, END_OF_MESSAGE not found'
        return None

    message = message.split(END_OF_MESSAGE)[0]
    return message
