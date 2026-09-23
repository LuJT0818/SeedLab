def xor(first, second):
    return bytearray(x^y for x, y in zip(first, second))

MSG = "This is a known message!"
HEX_1 = "a469b1c502c1cab966965e50425438e1bb1b5f9037a4c159"
HEX_2 = "bf73bcd3509299d566c35b5d450337e1bb175f903fafc159"



P1 = bytearray(MSG, 'utf-8')
C1 = bytearray.fromhex(HEX_1)
C2 = bytearray.fromhex(HEX_2)

P2 = xor(xor(P1, C1), C2)
RES = bytes(P2).decode('utf-8')

print(RES)