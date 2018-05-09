import math

def bytelist_to_int(list_value, littleendian=True):
    if not littleendian:
        list_value = list_value[::-1]
    res = 0
    for i, val in enumerate(list_value):
        res += val * 256**i
    return res

def int_to_bytelist(value,size=4, littleendian=True):
    res = [(value >> i*8) % 256 for i in range(size)]
    if not littleendian:
        res = res[::-1]
    return res

def str_to_bites(string):
    res = ''
    for ch in string:
        res += '{:08b}'.format(ord(ch))
    return res

def bites_to_str(bites):
    res = ''
    bites_len = len(bites)
    if bites_len % 8 != 0:
        raise ValueError("Bites string length must be multiple of eight, bites len is {}".format(bites_len))
    for i,ch in enumerate(bites):
        if ch not in ['0','1']:
            raise ValueError("Bit string must contain only '0' and '1', but char at position {} is {}".format(i,ch))
    for i in range(0, bites_len, 8):
        res += chr(int(bites[i:i+8],2))
    return res

def is_int(value, base):
    try:
        int(value, base)
        return True
    except ValueError:
        return False