from capstone import Cs, CS_ARCH_X86, CS_MODE_32
from keystone import Ks, KS_ARCH_X86, KS_MODE_32

_asm = Ks(KS_ARCH_X86, KS_MODE_32)

class Disasassembler:
    def __init__(self, offset = 0):
        self._disas = Cs(CS_ARCH_X86, CS_MODE_32)

        self.offset = offset


    def disasm(self, opcodes):
        return self._disas.disasm(opcodes, self.offset)

def asm(code):
    opcodes_list = _asm.asm(code)[0]
    return "".join(map(chr, opcodes_list))

