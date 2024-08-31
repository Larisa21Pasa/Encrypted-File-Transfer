from . import AESParameters


def multiplyGF(a, b):
    """
    Multiply two numbers in GF(2^8) with modulus 0x11B.

    Arguments:
    a -- First number
    b -- Second number

    Returns:
    The result of the multiplication.
    """
    result = 0
    while b:
        # XOR result with a if the least significant bit of b is set
        if b & 1:
            result ^= a
        # Left shift a
        a <<= 1
        # If a overflows beyond 8 bits
        if a & 0x100:
            # Reduce a modulo the irreducible polynomial
            a ^= AESParameters.modulus
        # Right shift b
        b >>= 1
    return result


def text_to_hex(text):
    """
    Convert a string to a hexadecimal string.

    Arguments:
    text -- The text string

    Returns:
    The hexadecimal string
    """
    result = ''
    for c in text:
        # 02x means: format the integer to a string with at least 2 digits, using zero-padding
        result += format(ord(c), '02x')
    return result


def convert_key_in_matrix(wkey, n):
    """
    Copy the round key from wkey starting at index n.

    Arguments:
    wkey -- The round key
    n -- The starting index

    Returns:
    The round key matrix
    """
    # 54 68 61 74 73 20 6D 79 20 4B 75 6E 67 20 46 75
    # result:
    # 54 73 20 67
    # 68 20 4B 20
    # 61 6D 75 46
    # 74 79 6E 75
    w = [[0 for _ in range(4)] for _ in range(4)]
    for i in range(AESParameters.nr_key_bytes):
        w[i % 4][i // 4] = wkey[i + n]
    return w


def convert_matrix_in_key(state):
    """
    From the state matrix, return the round key.

    Arguments:
    state -- The state matrix

    Returns:
    The round key
    """
    # 54 73 20 67
    # 68 20 4B 20
    # 61 6D 75 46
    # 74 79 6E 75
    # result:
    # 54 68 61 74 73 20 6D 79 20 4B 75 6E 67 20 46 75
    output = []
    for i in range(AESParameters.Nb):
        for j in range(AESParameters.Rows):
            output.append(state[j][i])
    return output

####################### FUNCTIONS FOR CIPHER#########################

def sub_word(word):
    """
    The transformation of words in which the S-box is applied to each
    of the four bytes of the word.

    Arguments:
    word -- A group of 32 bits that is treated either as a single entity
            or as an array of 4 bytes

    Returns:
    The array with bytes substituted using the S-box
    """
    substituted_word = list(word)
    for i in range(len(word)):
        # row = upper 4 bits of the byte
        # col = lower 4 bits of the byte
        upper_4_bits = (word[i] >> 4) & 0xF
        lower_4_bits = word[i] & 0xF

        # the substitution value would be determined by the intersection
        # of the row with index row and the column with index col
        substituted_word[i] = AESParameters.sBox[upper_4_bits][lower_4_bits]

    return substituted_word


def add_round_key(state, key):
    """
    The transformation of the state in which a round key is combined
    with the state

    Arguments:
    state -- The input matrix
    key -- The round key matrix

    Returns:
    The result of the AddRoundKey operation
    """
    output = [[0 for _ in range(len(state))] for _ in range(len(state))]

    for i in range(len(state)):
        for j in range(len(state[0])):
            # XOR each element of the input matrix
            # with the corresponding element of the round key matrix
            output[i][j] = state[i][j] ^ key[i][j]

    return output


def sub_bytes(state):
    """
    The transformation of the state that applies the S-box independently
    to each byte of the state

    Arguments:
    state -- The state matrix

    Returns:
    The result of the SubBytes operation
    """
    output = [[0 for _ in range(len(state))] for _ in range(len(state))]
    for i in range(len(state)):
        for j in range(len(state[0])):
            # row = upper 4 bits of the byte
            # col = lower 4 bits of the byte
            upper_4_bits = (state[i][j] >> 4) & 0xF
            lower_4_bits = state[i][j] & 0xF

            # the substitution value would be determined by the intersection
            # of the row with index row and the column with index col
            output[i][j] = AESParameters.sBox[upper_4_bits][lower_4_bits]
    return output


def shift_rows(state):
    """
    The transformation of the state in which the last three rows are
    cyclically shifted by different offsets

    Arguments:
    state -- The state matrix

    Returns:
    The result of the ShiftRows operation
    """
    # The elements on the main diagonal are shifted until they reach
    # the first column
    # [00, 10, 20, 30]     [00, 10, 20, 30]
    # [01, 11, 21, 31] --> [11, 21, 31, 01]
    # [02, 12, 22, 32]     [22, 32, 02, 12]
    # [03, 13, 23, 33]     [33, 03, 13, 23]
    new_state = [[0] * 4 for _ in range(4)]
    for i in range(len(state)):
        for j in range(len(state[0])):
            new_state[i][j] = state[i][(j + i) % 4]

    return new_state


def mix_columns(state):
    """
    The transformation of the state that takes all of the columns of the
    state and mixes their data (independently of one another) to produce
    new columns.

    Arguments:
    state -- The state matrix

    Returns:
    The result of the MixColumns operation
    """
    new_state = [[0] * len(state) for _ in range(len(state[0]))]

    # s0,c = ({02} • s0,c) ⊕ ({03} • s1,c) ⊕ s2,c ⊕ s3,c0
    # s1,c = s0,c ⊕ ({02} • s1,c) ⊕ ({03} • s2,c) ⊕ s3,c0
    # s2,c = s0,c ⊕ s1,c ⊕ ({02} • s2,c) ⊕ ({03} • s3,c)
    # s3,c = ({03} • s0,c) ⊕ s1,c ⊕ s2,c ⊕ ({02} • s3,c)
    for c in range(4):
        new_state[0][c] = (multiplyGF(state[0][c], 0x02) ^ multiplyGF(state[1][c], 0x03) ^ state[2][c] ^ state[3][c])
        new_state[1][c] = (state[0][c] ^ multiplyGF(state[1][c], 0x02) ^ multiplyGF(state[2][c], 0x03) ^ state[3][c])
        new_state[2][c] = (state[0][c] ^ state[1][c] ^ multiplyGF(state[2][c], 0x02) ^ multiplyGF(state[3][c], 0x03))
        new_state[3][c] = (multiplyGF(state[0][c], 0x03) ^ state[1][c] ^ state[2][c] ^ multiplyGF(state[3][c], 0x02))

    return new_state


def rot_word(word):
    """
    The transformation of words in which the four bytes
    of the word are permuted cyclically (shifted left).

    Arguments:
    word -- A list representing a word

    Returns:
    A new list obtained by rotating the elements of the
    input list to the left by one position.
    """

    # index 1 to end + index 0
    return word[1:] + word[:1]


####################### FUNCTIONS FOR INVCIPHER#########################

def inv_shift_rows(state):
    """
    Is the inverse of the SHIFTROWS(). In particular, the bytes in the
    last three rows of the state are cyclically shifted

    Arguments:
    state -- The state matrix

    Returns:
    The result of the InvShiftRows operation
    """
    # The elements are right shifted with line position
    # [00, 10, 20, 30]     [00, 10, 20, 30]
    # [11, 21, 31, 01] --> [01, 11, 21, 31]
    # [22, 32, 02, 12]     [02, 12, 22, 32]
    # [33, 03, 13, 23]     [03, 13, 23, 33]
    new_state = [[0] * 4 for _ in range(4)]
    for i in range(len(state)):
        for j in range(len(state[0])):
            new_state[i][j] = state[i][(j - i) % 4]

    return new_state


def inv_sub_bytes(state):
    """
    INVSUBBYTES() is the inverse of SUBBYTES(), in which the inverse of
    SBOX(), denoted by INVSBOX(), is applied to each byte of the state

    Arguments:
    state -- The state matrix

    Returns:
    The result of the InvSubBytes operation
    """
    output = [[0 for _ in range(len(state))] for _ in range(len(state))]
    for i in range(len(state)):
        for j in range(len(state[0])):
            # row = upper 4 bits of the byte
            # col = lower 4 bits of the byte
            upper_4_bits = (state[i][j] >> 4) & 0xF
            lower_4_bits = state[i][j] & 0xF

            # the substitution value would be determined by the intersection
            # of the row with index row and the column with index col
            output[i][j] = AESParameters.invSBox[upper_4_bits][lower_4_bits]
    return output


def inv_mix_columns(state):
    """
    INVMIXCOLUMNS() is the inverse of MIXCOLUMNS(). In particular,
    INVMIXCOLUMNS()multiplies each of the four columns of the state
    by a single fixed matrix, with its entries taken from the
    following word [a0,a1,a2,a3] = [{0e},{09},{0d},{0b}].

    Arguments:
    state -- The state matrix

    Returns:
    The result of the InvMixColumns operation
    """
    new_state = [[0] * len(state) for _ in range(len(state[0]))]

    # s0,c = ({0E} • s0,c) ⊕ ({0B} • s1,c) ⊕ ({0D} • s2,c) ⊕ ({09} • s3,c)
    # s1,c = ({09} • s0,c) ⊕ ({0E} • s1,c) ⊕ ({0B} • s2,c) ⊕ ({0D} • s3,c)
    # s2,c = ({0D} • s0,c) ⊕ ({09} • s1,c) ⊕ ({0E} • s2,c) ⊕ ({0B} • s3,c)
    # s3,c = ({0B} • s0,c) ⊕ ({0D} • s1,c) ⊕ ({09} • s2,c) ⊕ ({0E} • s3,c)
    for c in range(len(state[0])):
        new_state[0][c] = (multiplyGF(state[0][c], 0x0E) ^ multiplyGF(state[1][c], 0x0B) ^ multiplyGF(state[2][c],
                                                                                                      0x0D) ^ multiplyGF(
            state[3][c], 0x09))
        new_state[1][c] = (multiplyGF(state[0][c], 0x09) ^ multiplyGF(state[1][c], 0x0E) ^ multiplyGF(state[2][c],
                                                                                                      0x0B) ^ multiplyGF(
            state[3][c], 0x0D))
        new_state[2][c] = (multiplyGF(state[0][c], 0x0D) ^ multiplyGF(state[1][c], 0x09) ^ multiplyGF(state[2][c],
                                                                                                      0x0E) ^ multiplyGF(
            state[3][c], 0x0B))
        new_state[3][c] = (multiplyGF(state[0][c], 0x0B) ^ multiplyGF(state[1][c], 0x0D) ^ multiplyGF(state[2][c],
                                                                                                      0x09) ^ multiplyGF(
            state[3][c], 0x0E))

    return new_state


def inv_add_round_key(state, key):
    """
    The transformation of the state in which a round key is combined
    with the state

    Arguments:
    state -- The state matrix
    key -- The round key matrix

    Returns:
    The result of the InvAddRoundKey operation
    """
    output = [[0 for _ in range(len(state))] for _ in range(len(state))]

    for i in range(len(state)):
        for j in range(len(state[0])):
            # XOR each element of the input matrix
            # with the corresponding element of the round key matrix
            output[i][j] = state[i][j] ^ key[i][j]

    return output

