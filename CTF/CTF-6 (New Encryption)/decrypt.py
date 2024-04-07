import string

START = ord("a")
CHARSET = string.ascii_lowercase[:16]

def decode_b16(middle):
    decoded = ""
    for i in range(0, len(middle), 2):

        index1 = CHARSET.index(middle[i])      
        b1 = "{0:04b}".format(index1)
        if i + 1 < len(middle):            
            index2 = CHARSET.index(middle[i + 1])  
            b2 = "{0:04b}".format(index2)
            decoded += chr(int(b1 + b2, 2))
        else:
            decoded += chr(int(b1, 2))
    return decoded

def caesar_shift(c, k, i):
    index = CHARSET.index(c)
    value = (index - ord(k) + 2 * START) % len(CHARSET) + 97
    return (chr(int(value)))    

cipher = "jikmkjgekjkckjkbknkjlhgekflgkjgekbkfkpknkcklgekfgekbkdlkkjgcgejlkjgekckjkjkigelikdgekfkhligekkkflhligc"
for j in range(15):
    key = chr(j + 97)
    middle = ""
    for i, c in enumerate(cipher):
        middle += caesar_shift(c, key[i % len(key)],i)
    plain = decode_b16(middle)
    print("The plain text for key: " + key + " is: ")
    print(plain)
    print()