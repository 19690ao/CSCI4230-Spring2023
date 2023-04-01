import secrets

S_box = [
        '63 7c 77 7b f2 6b 6f c5 30 01 67 2b fe d7 ab 76'.split(' '),
        'ca 82 c9 7d fa 59 47 f0 ad d4 a2 af 9c a4 72 c0'.split(' '),
        'b7 fd 93 26 36 3f f7 cc 34 a5 e5 f1 71 d8 31 15'.split(' '),
        '04 c7 23 c3 18 96 05 9a 07 12 80 e2 eb 27 b2 75'.split(' '),
        '09 83 2c 1a 1b 6e 5a a0 52 3b d6 b3 29 e3 2f 84'.split(' '),
        '53 d1 00 ed 20 fc b1 5b 6a cb be 39 4a 4c 58 cf'.split(' '),
        'd0 ef aa fb 43 4d 33 85 45 f9 02 7f 50 3c 9f a8'.split(' '),
        '51 a3 40 8f 92 9d 38 f5 bc b6 da 21 10 ff f3 d2'.split(' '),
        'cd 0c 13 ec 5f 97 44 17 c4 a7 7e 3d 64 5d 19 73'.split(' '),
        '60 81 4f dc 22 2a 90 88 46 ee b8 14 de 5e 0b db'.split(' '),
        'e0 32 3a 0a 49 06 24 5c c2 d3 ac 62 91 95 e4 79'.split(' '),
        'e7 c8 37 6d 8d d5 4e a9 6c 56 f4 ea 65 7a ae 08'.split(' '),
        'ba 78 25 2e 1c a6 b4 c6 e8 dd 74 1f 4b bd 8b 8a'.split(' '),
        '70 3e b5 66 48 03 f6 0e 61 35 57 b9 86 c1 1d 9e'.split(' '),
        'e1 f8 98 11 69 d9 8e 94 9b 1e 87 e9 ce 55 28 df'.split(' '),
        '8c a1 89 0d bf e6 42 68 41 99 2d 0f b0 54 bb 16'.split(' ')
        ]
S_box_inv = [
            '52 09 6a d5 30 36 a5 38 bf 40 a3 9e 81 f3 d7 fb'.split(' '),
            '7c e3 39 82 9b 2f ff 87 34 8e 43 44 c4 de e9 cb'.split(' '),
            '54 7b 94 32 a6 c2 23 3d ee 4c 95 0b 42 fa c3 4e'.split(' '),
            '08 2e a1 66 28 d9 24 b2 76 5b a2 49 6d 8b d1 25'.split(' '),
            '72 f8 f6 64 86 68 98 16 d4 a4 5c cc 5d 65 b6 92'.split(' '),
            '6c 70 48 50 fd ed b9 da 5e 15 46 57 a7 8d 9d 84'.split(' '),
            '90 d8 ab 00 8c bc d3 0a f7 e4 58 05 b8 b3 45 06'.split(' '),
            'd0 2c 1e 8f ca 3f 0f 02 c1 af bd 03 01 13 8a 6b'.split(' '),
            '3a 91 11 41 4f 67 dc ea 97 f2 cf ce f0 b4 e6 73'.split(' '),
            '96 ac 74 22 e7 ad 35 85 e2 f9 37 e8 1c 75 df 6e'.split(' '),
            '47 f1 1a 71 1d 29 c5 89 6f b7 62 0e aa 18 be 1b'.split(' '),
            'fc 56 3e 4b c6 d2 79 20 9a db c0 fe 78 cd 5a f4'.split(' '),
            '1f dd a8 33 88 07 c7 31 b1 12 10 59 27 80 ec 5f'.split(' '),
            '60 51 7f a9 19 b5 4a 0d 2d e5 7a 9f 93 c9 9c ef'.split(' '),
            'a0 e0 3b 4d ae 2a f5 b0 c8 eb bb 3c 83 53 99 61'.split(' '),
            '17 2b 04 7e ba 77 d6 26 e1 69 14 63 55 21 0c 7d'.split(' ')
            ]



def xtime(num: int) -> int:
    if num >> 7 == 0:
        return num << 1
    return ((num << 1) ^ 0x1b) & 0xff

def mult_mod(byte1: str, byte2: str) -> str:
    num1 = int(byte1, 16)
    num2 = int(byte2, 16)

    res = num1 if (num2 % 2 == 1) else 0
    xVar = num1
    while num2 > 0:
        num2 = num2 >> 1
        xVar = xtime(xVar)

        if num2 % 2 == 1:
            res ^= xVar

    return format(res, '02x')


def string_to_state(msg: str) -> list:
    msg = [msg[i:i+2] for i in range(0, len(msg), 2)]

    state = []
    for r in range(4):
        state.append([])

        for c in range(4):
            state[r].append(msg[r + 4*c])

    return state

def state_to_string(state: list) -> str:
    res = []

    for c in range(4):
        for r in range(4):
            res.append(state[r][c])

    return ''.join(res)


def sub_bytes(state: list) -> None:
    for r in range(4):
        for c in range(4):
            byte = state[r][c]

            box_row = int(byte[0], 16)
            box_col = int(byte[1], 16)

            state[r][c] = S_box[box_row][box_col]


def inv_sub_bytes(state: list) -> None:
    for r in range(4):
        for c in range(4):
            byte = state[r][c]

            box_row = int(byte[0], 16)
            box_col = int(byte[1], 16)

            state[r][c] = S_box_inv[box_row][box_col]


def shift_rows(state: list) -> None:
    for r in range(4):
        copy = [c for c in state[r]]

        for c in range(4):
            state[r][c] = copy[(c + r) % 4]


def inv_shift_rows(state: list) -> None:
    for r in range(4):
        copy = [c for c in state[r]]

        for c in range(4):
            state[r][c] = copy[(c - r) % 4]


def xor_bytes(*args: str) -> str:
    res = 0
    for byte in args:
        res ^= int(byte, 16)

    return format(res, '02x')


def mix_columns(state: list) -> None:
    for c in range(4):
        copy = [state[r][c] for r in range(4)]

        state[0][c] = xor_bytes(mult_mod('02', copy[0]), mult_mod('03', copy[1]), copy[2], copy[3])
        state[1][c] = xor_bytes(copy[0], mult_mod('02', copy[1]), mult_mod('03', copy[2]), copy[3])
        state[2][c] = xor_bytes(copy[0], copy[1], mult_mod('02', copy[2]), mult_mod('03', copy[3]))
        state[3][c] = xor_bytes(mult_mod('03', copy[0]), copy[1], copy[2], mult_mod('02', copy[3]))

def inv_mix_columns(state: list) -> None:
    for c in range(4):
        copy = [state[r][c] for r in range(4)]

        state[0][c] = xor_bytes(mult_mod('0e', copy[0]), mult_mod('0b', copy[1]), mult_mod('0d', copy[2]), mult_mod('09', copy[3]))
        state[1][c] = xor_bytes(mult_mod('09', copy[0]), mult_mod('0e', copy[1]), mult_mod('0b', copy[2]), mult_mod('0d', copy[3]))
        state[2][c] = xor_bytes(mult_mod('0d', copy[0]), mult_mod('09', copy[1]), mult_mod('0e', copy[2]), mult_mod('0b', copy[3]))
        state[3][c] = xor_bytes(mult_mod('0b', copy[0]), mult_mod('0d', copy[1]), mult_mod('09', copy[2]), mult_mod('0e', copy[3]))


def add_round_key(state: list, key: list) -> None:
    for c in range(4):
        for r in range(4):
            val = int(state[r][c], 16) ^ int(key[c][r], 16)
            state[r][c] = format(val, '02x')


def sub_word(word: list) -> list:
    res = []
    for byte in word:
        box_x = int(byte[0], 16)
        box_y = int(byte[1], 16)

        res.append(S_box[box_x][box_y])
    
    return res


def rot_word(word: list) -> list:
    res = []
    for i in range(4):
        res.append(word[(i + 1) % 4])

    return res


def rc(i: int) -> int:
    if i == 1:
        return 1
    
    prev = rc(i-1)
    if prev < 0x80:
        return int(mult_mod('02', format(prev, '02x')), 16)
    return int(mult_mod('02', format(prev, '02x')), 16) ^ 0x1b


def rcon(i: int) -> list:
    return [format(rc(i), '02x'), '00', '00', '00']

def word_xor(word1: list, word2: list) -> list:
    res = [int(a, 16) ^ int(b, 16) for a, b in zip(word1, word2)]
    return [format(byte, '02x') for byte in res]


def key_expansion(key: list, key_length: int, num_rounds: int) -> list:
    keys = []

    i = 0
    while i < key_length:
        keys.append([key[4*i + j] for j in range(4)])
        i += 1

    i = key_length
    while i < 4 * (num_rounds + 1):
        temp = keys[i-1]
        if i % key_length == 0:
            temp = word_xor(sub_word(rot_word(temp)), rcon(i // key_length)) 
        elif key_length > 6 and i % key_length == 4:
            temp = sub_word(temp)
        keys.append(word_xor(keys[i - key_length], temp))
        
        i += 1

    return keys


def aes_encrypt_block(block: str, key: list) -> str:
    state = string_to_state(block)
    keys = key_expansion(key, 8, 14)

    add_round_key(state, keys[:4])

    for rnd in range(1, 14):
        sub_bytes(state)
        shift_rows(state)
        mix_columns(state)
        add_round_key(state, keys[rnd*4:(rnd+1)*4])

    sub_bytes(state)
    shift_rows(state)
    add_round_key(state, keys[14*4:15*4])

    return state_to_string(state)


def aes_decrypt_block(block: str, key: list) -> str:
    state = string_to_state(block)
    keys = key_expansion(key, 8, 14)

    add_round_key(state, keys[14*4:15*4]) 
    for rnd in range(13, 0, -1):
        inv_shift_rows(state)
        inv_sub_bytes(state)
        add_round_key(state, keys[rnd*4:(rnd+1)*4])
        inv_mix_columns(state)

    inv_shift_rows(state)
    inv_sub_bytes(state)
    add_round_key(state, keys[0:4])

    return state_to_string(state)

def block_xor(block1: str, block2: str) -> str:
    block1 = [block1[i:i+2] for i in range(0, len(block1), 2)]
    block2 = [block2[i:i+2] for i in range(0, len(block2), 2)]

    res = [int(a, 16) ^ int(b, 16) for a, b in zip(block1, block2)]
    return ''.join([format(byte, '02x') for byte in res])

def encrypt(msg: str, key: str) -> str:
    while len(msg) % 16 != 0:
        msg += '\x00'

    converted = ''.join([format(ord(c), '02x') for c in msg])

    blocks = [converted[i:i+32] for i in range(0, len(converted), 32)] 
    ciphers = []

    key = [key[i:i+2] for i in range(0, len(key), 2)]
    
    for block in blocks:
        if len(ciphers) > 0:
            block = block_xor(block, ciphers[-1]) # CBC
        ciphers.append(aes_encrypt_block(block, key))

    return ''.join(ciphers)

def decrypt(msg: str, key: str) -> str:
    blocks = [msg[i:i+32] for i in range(0, len(msg), 32)] 
    decrypted = []

    key = [key[i:i+2] for i in range(0, len(key), 2)]

    for i, block in enumerate(blocks):
        d = aes_decrypt_block(block, key)
        if i > 0:
            d = block_xor(d, blocks[i-1])
        decrypted.append(d)

    for i, block in enumerate(decrypted):
        decrypted[i] = ''.join([chr(int(block[i:i+2], 16)) for i in range(0, len(block), 2)])
    decrypted = ''.join(decrypted)
    return decrypted.rstrip('\x00') # remove padding

def generate_key() -> str:
    return format(secrets.randbits(32*8), '064x') 
