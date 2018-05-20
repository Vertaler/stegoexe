import lief
from random_nop import random_nop
from asm_utils import Disasassembler, asm
from binary_utils import light_expand_section, rebuild_binary

BLOCK_SIZE = 32
MINIMAL_SIZE_FOR_STEGO = 14
JMP_INSTR_LEN = 5


def insert_char(char, head, tail):
    nops_size = BLOCK_SIZE - len(head) - len(tail)
    print "expected {}, real {}".format(nops_size, len((random_nop(nops_size))))
    block = head + random_nop(nops_size) + tail
    return block


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
        jmp_operand = int(instr.op_str)
        if jmp_operand + instr.address >= len(block) or (jmp_operand + instr.address) < 0:
            jmp_operand -= (next_position - initial_position)
            asm_instr = asm(instr.mnemonic + ' ' + str(jmp_operand))
            if len(asm_instr) > len(instr.bytes):
                update_previous_jumps(instr.address, len(asm_instr) - len(instr.bytes))
        jmp_dict_operands[instr.address] = jmp_operand
        prev_jmp_list.push(instr)

    for instr in instr_list:
        if instr.address in jmp_dict_operands:
            str_operand = str(jmp_dict_operands[instr.address])
            res += asm(instr.mnemonic + ' ' + str_operand)
        else:
            res += str(instr.bytes)
    return res


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
        ret_find = False
        tail_len = 0
        while len(current_block + str(instr.bytes)) <= BLOCK_SIZE:
            current_block += str(instr.bytes)

            if not ret_find and instr.mnemonic == 'ret' and len(current_block) >= MINIMAL_SIZE_FOR_STEGO:
                ret_find = True
                tail_len = BLOCK_SIZE - len(current_block) - len(instr.bytes)
            if not ret_find and instr.mnemonic == 'ret' and len(current_block) < MINIMAL_SIZE_FOR_STEGO:
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

        new_block_head = current_block[:head_len] + jmp_asm(len(code) - BLOCK_SIZE * i -head_len)
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
