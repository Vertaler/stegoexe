import lief
from random_nop import random_nop
from asm_utils import Disasassembler, asm
from binary_utils import light_expand_section, rebuild_binary

BLOCK_SIZE = 20
JMP_INSTR_LEN = 5

def insert_char(char, head, tail):
    nops_size = BLOCK_SIZE - len(head) - len(tail)
    print "expected {}, real {}".format(nops_size, len((random_nop(nops_size))))
    block = head + random_nop(nops_size) + tail
    return block

def jmp_asm(address):
    return asm("jmp {}".format(address))

def insert_message(message, binary_path):
    binary = lief.parse(binary_path)
    entrypoint = binary.optional_header.addressof_entrypoint
    imagebase = binary.optional_header.imagebase
    code_section = binary.section_from_rva(entrypoint)
    code = "".join(map(chr, code_section.content))
    code_va = code_section.virtual_address + imagebase
    disas = Disasassembler(offset=0)
    disas_iter = iter(disas.disasm(code))
    light_expand_section(binary, code_section.name)
    current_block = ''
    head_len = len(current_block)
    for i, ch in enumerate(message):
        instr = disas_iter.next()
        while len(current_block + str(instr.bytes)) <= BLOCK_SIZE:
            current_block += str(instr.bytes)
            print instr.mnemonic + " " + instr.op_str
            instr = disas_iter.next()
        tail_len = BLOCK_SIZE - len(current_block)
        current_block += str(instr.bytes)[:tail_len]
        instructions_to_move =  current_block[head_len: BLOCK_SIZE-tail_len]
        instructions_to_move += jmp_asm(instr.address - len(code) - len(instructions_to_move))

        end_of_code = code_va + len(code)
        new_block_head = current_block[:head_len] + jmp_asm(len(code)-BLOCK_SIZE*i)
        new_block_tail = current_block[BLOCK_SIZE-tail_len:]
        new_block = insert_char(ch, new_block_head, new_block_tail)
        print len(new_block)
        code = code[:i*BLOCK_SIZE] + new_block + code[(i+1)*BLOCK_SIZE:] + instructions_to_move

        current_block = instr.bytes[tail_len:]
        head_len = len(current_block)

    new_code = map(ord, code)
    code_section.content = new_code
    binary.optional_header.dll_characteristics &= ~lief.PE.DLL_CHARACTERISTICS.DYNAMIC_BASE
    rebuild_binary(binary, "modified.exe")