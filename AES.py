import AESParameters
import utils


def key_expansion(key):
    """
    The routine that generates the round keys from the key.

    Arguments:
    key -- The original key

    Returns:
    A linear array of words
    """
    # Initialize the array for storing round keys
    w = bytearray(AESParameters.nr_key_bytes * (AESParameters.Nr + 1))
    i = 0

    # Copy the original key into the array (round key 0)
    while i < AESParameters.nr_key_bytes:
        w[i] = key[i]
        i += 1

    i = 4

    # Obtain the round keys (round key 1 to round key Nr)
    while i <= 4 * AESParameters.Nr + 3:
        # Initialize a temporary block with the last 4 bytes of the previous round key
        temp = w[4 * (i - 1): 4 * i]

        # Generate a special block for certain rounds
        if i % AESParameters.Nk == 0:
            # Rotate the bytes in the temporary block
            # Apply substitution operation
            rot_sub_output = utils.sub_word(utils.rot_word(temp))

            for idx in range(len(rot_sub_output)):
                temp[idx] = rot_sub_output[idx] ^ bytearray(AESParameters.Rcon[i // AESParameters.Nk])[idx]
        elif AESParameters.Nk > 6 and i % AESParameters.Nk == 4:
            temp = utils.sub_word(temp)

        # Put the round key into the array
        for j in range(4):
            w[4 * i + j] = temp[j] ^ w[4 * (i - AESParameters.Nk) + j]

        i += 1

    return w


def cipher(to_encrypt, wkey):
    """
    The transformation of blocks that underlies AES-128;
    the key schedule and the number of rounds are
    parameters of the transformation

    Arguments:
    input -- The input data
    wkey -- The round keys, result from key_expansion

    Returns:
    The encrypted data
    """
    # state = intermediate result of the AES block cipher that is represented as a
    # two-dimensional array of bytes with four rows and Nb columns
    state = utils.convert_key_in_matrix(to_encrypt, 0)

    # Round key for the first round
    w = utils.convert_key_in_matrix(wkey, 0)

    # Initial round key addition
    state = utils.add_round_key(state, w)

    # The state matrix is transformed Nr times
    for round in range(1, AESParameters.Nr):
        state = utils.sub_bytes(state)
        state = utils.shift_rows(state)
        state = utils.mix_columns(state)
        # wkey is a string with 16 bytes for each round key
        # total of 16 * Nr bytes. For each round, we extract
        # 16 bytes from wkey and convert it to a 4x4 matrix
        w = utils.convert_key_in_matrix(wkey, 16 * round)
        state = utils.add_round_key(state, w)

    # The final round
    state = utils.sub_bytes(state)
    state = utils.shift_rows(state)
    w = utils.convert_key_in_matrix(wkey, 16 * AESParameters.Nr)
    state = utils.add_round_key(state, w)

    # Obtain the output from the state matrix
    output = utils.convert_matrix_in_key(state)

    return output


def inv_cipher(to_decrypt, wkey):
    """
    The transformations in the specifcation of CIPHER()
    are inverted and executed in reverse order

    Arguments:
    input -- The input data
    wkey -- The round keys, result from key_expansion

    Returns:
    The decrypted data
    """
    # state = intermediate result of the AES block cipher that is represented as a
    # two-dimensional array of bytes with four rows and Nb columns
    state = utils.convert_key_in_matrix(to_decrypt, 0)

    # Round key for the first round (which is the last round key)
    w = utils.convert_key_in_matrix(wkey, 16 * AESParameters.Nr)

    # Initial round key addition
    state = utils.add_round_key(state, w)

    # The state matrix is transformed Nr times
    for round in range(AESParameters.Nr - 1, 0, -1):
        state = utils.inv_shift_rows(state)
        state = utils.inv_sub_bytes(state)
        w = utils.convert_key_in_matrix(wkey, 16 * round)
        state = utils.add_round_key(state, w)
        state = utils.inv_mix_columns(state)

    # The final round (which is the first round key)
    state = utils.inv_shift_rows(state)
    state = utils.inv_sub_bytes(state)
    w = utils.convert_key_in_matrix(wkey, 0)
    state = utils.add_round_key(state, w)

    # Obtain the output from the state matrix
    output = utils.convert_matrix_in_key(state)

    return output


def encrypt(input_str, key):
    """
    Encrypts the input string using AES block cipher.

    Arguments:
    input_str -- The input string to be encrypted
    key -- The encryption key

    Returns:
    The encrypted data
    """
    bytes_input = input_str.encode('utf-8')

    input_len = len(bytes_input)
    len_padded = input_len + (16 - input_len % 16)

    # Pad the input data to a multiple of 16 bytes using zero bytes
    byt = bytes_input.ljust(len_padded, b'\x00')

    wkey = key_expansion(key)

    # Encrypt each 16-byte block using the AES cipher and previously calculated round keys
    encrypted_blocks = [bytes(cipher(byt[i:i + 16], wkey)) for i in range(0, len(byt), 16)]

    # Concatenate the encrypted blocks into a single bytearray
    output = bytearray().join(encrypted_blocks)

    return output


def decrypt(input_data, key):
    """
    Decrypts the input data using AES block cipher.

    Arguments:
    input_data -- The input data to be decrypted
    key -- The decryption key

    Returns:
    The decrypted string
    """

    # Check if the input data length is a multiple of 16 (AES block size)
    if len(input_data) % 16 != 0:
        # Raise an exception if the input data length is invalid
        raise Exception("Invalid input length")

    # Expand the given key to obtain round keys for each round of the AES cipher
    wkey = key_expansion(key)

    # Iterate through each 16-byte block in the input data and decrypt
    decrypted_blocks = [bytes(inv_cipher(input_data[i:i + 16], wkey)) for i in range(0, len(input_data), 16)]

    # Concatenate the decrypted blocks into a single bytearray
    output = bytearray().join(decrypted_blocks)

    # Decode the resulting bytes into a string and remove padding characters
    return output.decode('utf-8').rstrip('\x00')
