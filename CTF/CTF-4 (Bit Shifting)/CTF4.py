with open('bits.txt', 'rb') as file:
    flag = file.read()

decoded = []

for i in range(0, len(flag), 2):
    # Two bytes to integer.
    btoi = flag[i] << 8 | flag[i+1]
    # First byte.
    decoded.append(chr(btoi >> 8))
    # Second byte.
    decoded.append(chr(btoi & 255))

print("".join(decoded))
