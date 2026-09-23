def xor(first, second):
    return bytearray(x^y for x, y in zip(first, second))

HEX_1 = input("P:")
HEX_2 = input("IV1:")
HEX_3 = input("IV2:")

C1 = bytearray.fromhex(HEX_1)
C2 = bytearray.fromhex(HEX_2)
C3 = bytearray.fromhex(HEX_3)

RES = xor(C1, xor(C2, C3))

print("C:")
print(''.join('{:02x}'.format(b) for b in RES))