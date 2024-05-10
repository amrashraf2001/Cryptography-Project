def read_file(file_name):
    with open(file_name, 'r', encoding='ISO-8859-1') as file:
        data = file.read()
    return data

def text_to_binary(text):
    binary_data = ''.join(format(ord(char), '08b') for char in text)
    return binary_data

def binary_to_text(binary_data):
    text = ''.join(chr(int(binary_data[i:i+8], 2)) for i in range(0, len(binary_data), 8))
    return text

def shift(binary_data, i):
    shifted_data = binary_data[i:] + binary_data[0]
    return shifted_data

file_name = 'bits.txt'
original_data = read_file(file_name)
binary_data = text_to_binary(original_data)

for i in range(len(original_data)):
    shifted_data = shift(binary_data, i)
    modified_text = binary_to_text(shifted_data)
    print("Modified text: ", modified_text, " with circular shift:", i, '\n')
