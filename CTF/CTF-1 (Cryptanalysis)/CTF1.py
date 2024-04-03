from collections import Counter

f = open("statistics.txt", "w")

with open('encrypted_text.txt', 'r') as file:
    encrypted_text = file.read()

character_count = Counter(encrypted_text)

for char, count in character_count.items():
        print(f"Character '{char}' appears {count} times.")
        f.write(f"Character '{char}' appears {count} times.\n\n")
        print() 
f.close()

# Define a dictionary to map the letters to their replacements
letter_mapping = {
    'I': 'e',
    'R': 'i',
    'V': 's',
    'M': 'n',
    'K': 't',
    'P': 'o',
    'H': 'h',
    'E': 'a',
    'B': 'r',
    'S': 'g',
    'Q': 'v',
    'O': 'd',
    'X': 'u',
    'T': 'b',
    'W': 'y',
    'Y': 'w',
    'N': 'f',
    'C': 'l',
    'G': 'p',
    'U': 'm',
    'A': 'c',
    'L': 'k',
    'J': 'x',
    'Z': 'z',
    'D': 'j',
    'F': 'q',
}

f = open("decrypted_text.txt", "w")

# Replace the letters in the encrypted text
decrypted_text = ''
for char in encrypted_text:
    if char in letter_mapping:
        decrypted_text += letter_mapping[char]
    else:
        decrypted_text += char

f.write(decrypted_text)
f.close()

print(decrypted_text)
