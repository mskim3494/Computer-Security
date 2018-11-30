# CNET mskim3494
# Min Su Kim
# Note to Graders:
# I saved the text for question 1 in a file called 'ciphertext.txt'
# and saved the general frequencies for English in a file 'letter_freq.data'
# saved the text to cipher in a file 'plain_text.txt'

import numpy as np
import pandas as pd
from collections import Counter

# Question 1

text_file = open('ciphertext.txt')
ciphertext = ''
for line in text_file:
    ciphertext += line.strip()

# Following Kasiski attack
# First look at the mean variance of letters based on key length
# There will be a sharp increase for the length of the key and multiples
# Got a hint from doing Q2 first

# Helper functions
def GetVariance(text):
    c = Counter()
    c += Counter(text)
    N = sum(c.values())
    #normalize
    freqs = np.array([x/N for x in c.values()])
    return np.var(freqs)

def GetKeyVars(encrypted_m, length):
    txt_len = len(encrypted_m)
    ret = list()
    count = 0
    for each in range(length):
        to_append = list()
        i = count
        while i < txt_len:
            to_append.append(encrypted_m[i])
            i += length
        temp = ''.join(to_append)
        ret.append(GetVariance(temp))
        count += 1
    return ret

# Thought that the key would be within 10 characters
freq_list = list()
for i in range(1,10):
    freq_list.append(np.mean(GetKeyVars(ciphertext, i)))

print (freq_list)

# By looking at the variances, there is a noticeable spike when i = 7
# Confirm by looking at multiples of 7

print(np.mean(GetKeyVars(ciphertext, 14)))
print(np.mean(GetKeyVars(ciphertext, 21)))

# Visibly higher variance, so Key_length = 7
key_length = 7

# Get 7 texts, getting every 7th letter, to do frequency analysis
freq_analysis = list()
for i in range(0,key_length):
    j = i
    freq_analysis.append('')
    while j < len(ciphertext):
        freq_analysis[i] += (ciphertext[j])
        j += key_length

# Now do frequency analysis on each list and look for highest ones,
# correlate them to those in the English language

def GetFreqs(text):
    c = Counter()
    c += Counter(text)
    N = sum(c.values())
    #normalize
    freqs = list(c.items())
    for i in range(len(freqs)):
        freqs[i] = list(freqs[i])
    return sorted(freqs, key=lambda x: x[1])


# comparing it to freqs of English generally
# Look at each of the divided letter groups, and map the 
# most commonly repeated letter to E and check for consistency

# 1st letter map E -> A, L
# 2nd letter map E -> N, R
# 3rd letter map E -> S, W, O
# 4th letter map E -> A, K, J
# 5th letter map E -> H
# 6th letter map E -> X, R, M
# 7th letter map E -> R, G
# ANSAHXR, LNSAHXR, ARSAHXR, LRSAHXR, 

# Uppercase ASCII to number conversion = 65
def GetOffset(map_from, map_to):
    m_from = ord(map_from) - 65
    m_to = ord(map_to) - 65
    return chr(((m_to - m_from) % 26) + 65)

def GetKey(mapped):
    temp = [ord(x) - 65 for x in mapped]
    e_value = ord('E') - 65
    return ''.join([chr(((x-e_value)%26)+65) for x in temp])

possible_maps = list(('ANSAHXR', 'LNSAHXR', 'ARSAHXR', 'LRSAHXR', 'ANSKHXR'))
possible_keys = [GetKey(x) for x in possible_maps]
# Get the possible encryption key, and run it through 
# the decryption code

def Decrypt(text, key):
    M_map = list(ord(x)-65 for x in text)
    # Create a key map the length of the message
    key_len = len(key)
    key_offset = list(ord(x)-65 for x in key)
    K_map = list()
    N = len(M_map)
    count = 0
    while (count + key_len) < N :
        K_map += key_offset
        count += key_len
    if len(K_map) < N:
        K_map += key_offset[:N-len(K_map)]
    # Decryption
    D = [(m-k) % 26 for m, k in zip(M_map, K_map)]
    return ''.join([chr(x+65) for x in D])

# First guess : WJOWDTN // no result
# Other guesses : ['WJOWDTN', 'HJOWDTN', 'WNOWDTN', 'HNOWDTN', 'WJOGDTN']
# Try combinations of the possible keys, based on probability
# and check the resulting text
# YRYPTZGNAPHYTS from key = 'WNOWDTN'. looks like CRYPTOGRAPHY
# adjust 1st and 6th, X? - W = Y (mod 26). solve for x (S) 
# similarly for 6th, getting key = 'SNOWDEN'

print(Decrypt(ciphertext,'SNOWDEN'))

# ================================================================== #
# ================================================================== #
# ================================================================== #

# Question 2a
data = pd.read_csv('letter_freq.data')
freqs = np.array(data['frequency'])
u = np.mean(freqs)
N = len(freqs)

def Deviation(freq):
    return (freq - u) ** 2
print('Letter Frequency Variance, General English:')
print(np.var(freqs))

# Question 2b
# Extract text with the specific plaintext
text_file = open('plain_text.txt')
text = ''
for line in text_file:
    text += line.rstrip()
    
print('Letter Frequency Variance, Specific Text:')
print (GetVariance(text))

# Question 2c
# Convert letters to numbers, mapping 0-25 for a-z
M_map = list(ord(x)-97 for x in text)

def Encrypt(M_map, key):
    # Create a key map the length of the message
    key_len = len(key)
    key_offset = list(ord(x)-97 for x in key)
    K_map = list()
    N = len(M_map)
    count = 0
    while (count + key_len) < N :
        K_map += key_offset
        count += key_len
    if len(K_map) < N:
        K_map += key_offset[:N-len(K_map)]
    # Encryption
    E = [(m+k) % 26 for m, k in zip(M_map, K_map)]
    return ''.join([chr(x+97) for x in E])

key1 = 'yz'
key2 = 'xyz'
key3 = 'wxyz'
key4 = 'vwxyz'
key5 = 'uvwxyz'

print('Population variance of encrypted text by key:')
E_key1 = Encrypt(M_map, key1)
print (GetVariance(E_key1))
E_key2 = Encrypt(M_map, key2)
print (GetVariance(E_key2))
E_key3 = Encrypt(M_map, key3)
print (GetVariance(E_key3))
E_key4 = Encrypt(M_map, key4)
print (GetVariance(E_key4))
E_key5 = Encrypt(M_map, key5)
print (GetVariance(E_key5))

# Question 2d
def GetCipherVars(encrypted_m, key):
    key_len = len(key)
    txt_len = len(encrypted_m)
    ret = list()
    count = 0
    for each in key:
        to_append = list()
        i = count
        while i < txt_len:
            to_append.append(encrypted_m[i])
            i += key_len
        temp = ''.join(to_append)
        ret.append(GetVariance(temp))
        count += 1
    return ret

print('Mean population variances by key:')
cipher1 = np.mean(GetCipherVars(E_key1, key1))
print (np.mean(cipher1))
cipher2 = GetCipherVars(E_key2, key2)
print (np.mean(cipher2))
cipher3 = GetCipherVars(E_key3, key3)
print (np.mean(cipher3))
cipher4 = GetCipherVars(E_key4, key4)
print (np.mean(cipher4))
cipher5 = GetCipherVars(E_key5, key5)
print (np.mean(cipher5))

# Question 2e

key5_1 = GetKeyVars(E_key5, 2)
key5_2 = GetKeyVars(E_key5, 3)
key5_3 = GetKeyVars(E_key5, 4)
key5_4 = GetKeyVars(E_key5, 5)
key5_5 = GetKeyVars(E_key5, 6)

print('Population variance by length for key5:')
print(np.mean(key5_1))
print(np.mean(key5_2))
print(np.mean(key5_3))
print(np.mean(key5_4))

# Yes. Explain the Kasiski attack and the fact that this is a form of frequency analysis
