"""
Semantically Secure Simplified DES
"""

import random

VERBOSE = True

def text_to_bin_list(plaintext):
    """
    Convert text to list of binary representation of its ASCII code points
    """
    bin_list = []
    for char in plaintext:
        code_point = ord(char)
        binary = bin(code_point)[2:].zfill(8)
        bin_list.append(int(binary, 2))
    return bin_list

def bin_list_to_text(bin_list):
    """
    Convert list of binary representation of ASCII code points to text
    """
    plaintext = ""
    for binary in bin_list:
        code_point = int(binary)
        char = chr(code_point)
        plaintext += char
    return plaintext

def bin_list_to_str(binary_representation):
    """
    Convert a list of binary to string representation
    """
    binary_string = ""
    for byte in binary_representation:
        binary = bin(byte)[2:].zfill(8)
        binary_string += binary + " "
    return binary_string

def p10(initial_key):
    """
    Perform P10 permutation on the given 10-bit binary representation
    """
    perm_list = [3, 5, 2, 7, 4, 10, 1, 9, 8, 6]
    old_size = 10
    new_size = len(perm_list)
    scrambled_key = [0] * new_size
    for i, bit_index in enumerate(perm_list):
        scrambled_key[i] = (initial_key >> (old_size - bit_index)) & 1
    ans = int("".join(str(bit) for bit in scrambled_key), 2)
    return ans

def p8(initial_key):
    """
    Perform P8 permutation on the given 10-bit binary representation
    """
    perm_list = [6, 3, 7, 4, 8, 5, 10, 9]
    old_size = 10
    new_size = len(perm_list)
    scrambled_key = [0] * new_size
    for i, bit_index in enumerate(perm_list):
        scrambled_key[i] = (initial_key >> (old_size - bit_index)) & 1
    ans = int("".join(str(bit) for bit in scrambled_key), 2)
    return ans

def split_binary(binary_representation, size):
    """
    Split the given binary representation into two parts with equal length
    """
    assert size % 2 == 0, "Size must be even"
    half_size = size // 2
    left_half = binary_representation >> half_size
    right_half = binary_representation & (2 ** half_size - 1)
    return (left_half, right_half)

def circular_left_shift(binary_representation, size, shift):
    """
    Perform a circular left shift on a binary representation.
    """
    shift = shift % size
    shifted = binary_representation << shift & (2 ** size - 1) | \
        (binary_representation >> (size - shift))
    return shifted

def concat_binary(binary1, binary2, size, reverse=False):
    """
    Concatenate two binary numbers.
    """
    if reverse:
        return (binary2 << size) | binary1
    return (binary1 << size) | binary2

def initialize_rounds(initial_key):
    """
    Returns the two 5-bit parts of the initial 10-bit key after applying the Permutation-10 (P10) function.
    """
    return split_binary(p10(initial_key), 10)

def initial_perm(binary_representation):
    """
    Performs the initial permutation on the 8-bit binary representation.
    """
    perm_list = [2, 6, 3, 1, 4, 8, 5, 7]
    old_size = 8
    new_size = len(perm_list)
    scrambled_key = [0] * new_size
    for i, bit_index in enumerate(perm_list):
        scrambled_key[i] = (binary_representation >> (old_size - bit_index)) & 1
    return int("".join(str(bit) for bit in scrambled_key), 2)

def inverse_initial_perm(binary_representation):
    """
    Performs the inverse of the initial permutation on the 8-bit binary representation.
    """
    perm_list = [4, 1, 3, 5, 7, 2, 8, 6]
    old_size = 8
    new_size = len(perm_list)
    scrambled_key = [0] * new_size
    for i, bit_index in enumerate(perm_list):
        scrambled_key[i] = (binary_representation >> (old_size - bit_index)) & 1
    return int("".join(str(bit) for bit in scrambled_key), 2)

def expansion_perm(binary_representation):
    """
    Perform an expansion permutation on a 4-bit binary representation.
    """
    perm_list = [4, 1, 2, 3, 2, 3, 4, 1]
    old_size = 4
    new_size = len(perm_list)
    scrambled_key = [0] * new_size
    for i, bit_index in enumerate(perm_list):
        scrambled_key[i] = (binary_representation >> (old_size - bit_index)) & 1
    return int("".join(str(bit) for bit in scrambled_key), 2)

def s_boxes(binary1, binary2):
    """
    This function takes two 4-bit binary values as inputs, maps them to corresponding
    indices in two pre-defined S-Box matrices (sbox1 and sbox2), and returns the
    2-bit values stored in those indices.
    """
    sbox1 = [\
        [1, 0, 3, 2],\
        [3, 2, 1, 0],\
        [0, 2, 1, 3],\
        [3, 1, 3, 2]]
    sbox2 = [\
        [0, 1, 2, 3],\
        [2, 0, 1, 3],\
        [3, 0, 1, 0],\
        [2, 1, 0, 3]]
    row1 = int(bin(binary1)[2:].zfill(4)[0] + bin(binary1)[2:].zfill(4)[3], 2)
    row2 = int(bin(binary2)[2:].zfill(4)[0] + bin(binary2)[2:].zfill(4)[3], 2)
    col1 = int(bin(binary1)[2:].zfill(4)[1:3], 2)
    col2 = int(bin(binary2)[2:].zfill(4)[1:3], 2)

    res1 = sbox1[row1][col1]
    res2 = sbox2[row2][col2]
    return (res1, res2)

def p4(binary_representation):
    """
    Perform P4 permutation on the given binary representation
    """
    perm_list = [2, 4, 3, 1]
    old_size = 4
    new_size = len(perm_list)
    scrambled_key = [0] * new_size
    for i, bit_index in enumerate(perm_list):
        scrambled_key[i] = (binary_representation >> (old_size - bit_index)) & 1
    return int("".join(str(bit) for bit in scrambled_key), 2)

def f_func(binary_representation, round_key):
    """
    This function implements the key mixing function (f).
    """
    tmp = expansion_perm(binary_representation)
    tmp = tmp ^ round_key
    tmp = split_binary(tmp, 8)
    tmp = s_boxes(*tmp)
    tmp = concat_binary(*tmp, 2)
    tmp = p4(tmp)
    return tmp

def encrypt(plaintext, initial_key, round_count, iv=0):
    """
    Encrypts data using DES
    """
    if VERBOSE:
        print(f"Plaintext: \t{bin_list_to_str(plaintext)}")
        print(f"Initial Key: \t{bin(initial_key)[2:].zfill(10)}")
    xor_vector = iv
    cyphertext = []
    for old_block in plaintext:
        block = old_block^xor_vector
        round_prep = initialize_rounds(initial_key)
        text_prep = concat_binary(*split_binary(initial_perm(block), 8), 4, True)
        for i in range(round_count):
            round_key = round_prep
            round_prep = (circular_left_shift(round_prep[0], 5, i+1), circular_left_shift(round_prep[1], 5, i+1))
            round_key = concat_binary(round_prep[0], round_prep[1], 5)
            round_key = p8(round_key)
            tmp = split_binary(text_prep, 8)
            left_side = tmp[0]
            right_side = tmp[1]
            text_prep = concat_binary(right_side, left_side ^ f_func(right_side, round_key), 4)
        cyphertext.append(inverse_initial_perm(concat_binary(*split_binary(text_prep, 8), 4, True) ))
        xor_vector = cyphertext[-1]

    return cyphertext

def decrypt(cyphertext, initial_key, round_count, iv=0):
    """
    Decrypts data using DES
    """
    if VERBOSE:
        print(f"Cyphertext: \t{bin_list_to_str(cyphertext)}")
        print(f"Initial Key: \t{bin(initial_key)[2:].zfill(10)}")
    round_prep = initialize_rounds(initial_key)
    
    round_keys = []
    for i in range(round_count):
        round_key = round_prep
        round_prep = (circular_left_shift(round_prep[0], 5, i+1), circular_left_shift(round_prep[1], 5, i+1))
        round_key = concat_binary(round_prep[0], round_prep[1], 5)
        round_key = p8(round_key)
        round_keys.append(round_key)
    round_keys.reverse()
    xor_vector = iv
    plaintext = []
    for block in cyphertext:
        text_prep = concat_binary(*split_binary(initial_perm(block), 8), 4, False)
        for i in range(round_count):
            round_key = round_keys[i]
            tmp = split_binary(text_prep, 8)
            left_side = tmp[0]
            right_side = tmp[1]
            text_prep = concat_binary(right_side, left_side ^ f_func(right_side, round_key), 4)
        plaintext.append(inverse_initial_perm(concat_binary(*split_binary(text_prep, 8), 4, False) )^xor_vector)
        xor_vector = block
    return plaintext

def random_padding(plaintext, reverse=False):
    size = len(plaintext)
    padding_list = [random.randint(0,255) for _ in range(size)]
    ans = []
    if reverse:
        ans = padding_list+plaintext
    else:
        ans = plaintext+padding_list
    if VERBOSE:
        print(f"W/ Padding: \t{bin_list_to_str(ans)}")
        print(f"As text: \t{bin_list_to_text(ans)}")
    return ans

def inverse_random_padding(cyphertext, reverse=False):
    size = len(cyphertext)//2
    assert size % 2 == 0
    ans = []
    if reverse:
        ans = cyphertext[size:]
    else:
        ans = cyphertext[:size]
    if VERBOSE:
        print(f"W/out Padding: \t{bin_list_to_str(ans)}")
        print(f"As text: \t{bin_list_to_text(ans)}")
    return ans


if __name__ == "__main__":
    plaintext_string = "crypto"
    round_count = 2
    iv = random.randint(0,255)
    print(f"Encrypt/Decrypt \"{plaintext_string}\"\n")
    plaintext = text_to_bin_list(plaintext_string)
    plaintext = random_padding(plaintext)
    initial_key = int("1100011110", 2)
    print("ENCRYPT")
    cyphertext = encrypt(plaintext, initial_key, round_count, iv)
    print(f"Cyphertext: \t{bin_list_to_str(cyphertext)}")

    print("\nDECRYPT")
    decrypted = decrypt(cyphertext, initial_key, round_count, iv)
    print(f"Decryption: \t{bin_list_to_str(decrypted)}")
    assert plaintext == decrypted
    assert text_to_bin_list(plaintext_string) == inverse_random_padding(decrypted)
    
    print("\nSUCCESS: 'plaintext' is the same as 'decrypted'")
