import re
from collections import Counter

text = open('ciphertext.txt', encoding='utf-8').read()

letters = re.findall(r'[a-z]', text)
single = Counter(letters).most_common()

frequency_table = {
    'A' : 8.55, 'B' : 1.60, 'C' : 3.16, 'D' : 3.87, 'E' : 12.10, 'F' : 2.18, 
    'G' : 2.09, 'H' : 4.96, 'I' : 7.33, 'J' : 0.22, 'K' : 0.81, 'L' : 4.21, 
    'M' : 2.53, 'N' : 7.17, 'O' : 7.47, 'P' : 2.07, 'Q' : 0.10, 'R' : 6.33, 
    'S' : 6.73, 'T' : 8.94, 'U' : 2.68, 'V' : 1.06, 'W' : 1.83, 'X' : 0.19, 
    'Y' : 1.72, 'Z' : 0.11  
}
frequency_table = sorted(frequency_table, key=frequency_table.get, reverse=True)
# single = [element[0] for element in single]
print(single)
print(frequency_table)


words = re.findall(r'[a-z]+', text)

bigrams = Counter()
for w in words:
    for i in range(len(w) - 1):
        bigrams[w[i:i+2]] += 1
double = [d for d, _ in bigrams.most_common(30)]
bigram_frequencies = ['th', 'he', 'in', 'er', 'an', 're', 'es', 'on', 'st',
                   'nt', 'en', 'at', 'ed', 'nd', 'to', 'or', 'ea', 'ti',
                   'ar', 'te', 'ng', 'al', 'it', 'as', 'is', 'ha', 'et',
                   'se', 'ou', 'of']    
# print(double)
# print(bigram_frequencies)


trigrams = Counter()
for w in words:
    for i in range(len(w) - 2):
        trigrams[w[i:i+3]] += 1
triple = [d for d, _ in trigrams.most_common(30)]
trigram_frequencies = ['THE', 'AND', 'ING', 'ENT', 'ION', 'HER', 'FOR', 'THA', 'NTH',
                   'INT', 'ERE', 'TIO', 'TER', 'EST', 'ERS', 'ATI', 'HAT', 'ATE',
                   'ALL', 'ETH', 'HES', 'VER', 'HIS', 'OFT', 'ITH', 'FTH', 'STH',
                   'OTH', 'RES', 'ONT']    
# print(triple)
# print(trigram_frequencies)

common_english_words = ['THE', 'OF', 'AND', 'TO', 'A', 'IN', 'IS', 'FOR', 'THAT',
                   'WAS', 'ON', 'WITH', 'HE', 'IT', 'AS', 'AT', 'HIS', 'BY',
                   'BE', 'FROM', 'ARE', 'THIS', 'I', 'BUT', 'HAVE', 'AN', 'HAS',
                   'NOT', 'THEY', 'OR']    

ciphertext = re.findall(r'[a-z \n]', text)
encryption_key = {'a': 'C', 'b': 'F', 'c': 'M', 'd': 'Y', 'e': 'P', 'f': 'V', 'g': 'B',
                  'h': 'R', 'i': 'L', 'j': 'Q', 'k': 'X', 'l': 'W', 'm': 'I', 'n': 'E',
                  'o': 'J', 'p': 'D', 'q': 'S', 'r': 'G', 's': 'K', 't': 'H', 'u': 'N',
                  'v': 'A', 'w': 'Z', 'x': 'O', 'y': 'T', 'z': 'U'
                  }

plaintext = ''.join(encryption_key.get(ch, ch) for ch in ciphertext)
# print(plaintext)

with open('plaintext.txt', 'w', encoding='utf-8') as f:
    f.write(plaintext)

