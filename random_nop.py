import random
from asm_utils import asm

INT_32_MIN = -2147483648
INT_32_MAX = 2147483647

registers = ["eax", "ebx", "ecx", "edx", "edi", "esi", "ebp", "esp"]


def random_reg():
    return random.choice(registers)


# functions for random nops
def push_pop_1():
    return "push 0x{:08x};add esp,4;".format(random.randint(0, 2 ** 32))


def add_0():
    return "add {}, 0".format(random_reg())


def push_pop_2():
    return "push {0};pop {0};".format(random_reg())


def push_pop_3():
    return "push {0};add esp,4;".format(random_reg())


def add_sub():
    value = random.randint(INT_32_MIN, INT_32_MAX)
    reg = random_reg()
    res = "add {0}, {1};sub {0}, {1};".format(reg, value)
    return res


def simple_nop():
    return "nop;"


# key is opcode size
nop_dict = {
    1: simple_nop,
    2: push_pop_2,
    3: add_0,
    4: push_pop_3,
    8: push_pop_1,
}

random_size_nopes = [simple_nop, push_pop_1, push_pop_2, push_pop_3, add_0, add_sub]


def random_nop(size):
    res = ''
    allowable_sizes = nop_dict.keys()
    # choose random size nop
    while size >= 10:
        nop = random.choice(random_size_nopes)()
        asm_nop = asm(nop)
        nop_size = len(asm_nop)
        # print "instr: {} real size: {}".format(nop, nop_size)
        if nop_size > size:
            continue
        else:
            res += asm(nop)
            size -= nop_size

    # choose nop of deterministic size
    while size != 0:
        allowable_sizes = filter(lambda x: x <= size, allowable_sizes)
        key = random.choice(allowable_sizes)
        nop = nop_dict[key]()
        # print "instr: {} expected size: {} real size: {}".format(nop, key, len(asm(nop)))
        res += asm(nop)
        size -= key
    print '-------------------'
    return res
