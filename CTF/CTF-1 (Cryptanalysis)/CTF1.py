from collections import Counter
import re

with open('encrypted_text.txt', 'r') as file:
    encrypted_text = file.read()

encrypted_text = re.sub(r'[^a-zA-Z]', '', encrypted_text).upper()
letter_freq = Counter(encrypted_text)
sorted_freq = letter_freq.most_common()


english_freq = 'etoahinsrdlcumwfgypbvkjxqz'
mapping = {}
for i in range(len(sorted_freq)):
    mapping[sorted_freq[i][0]] = english_freq[i]

decrypted_text = ''.join(mapping.get(char, char) for char in encrypted_text)
print(sorted_freq)
print(decrypted_text)
