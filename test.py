import utils
import AES
import AESParameters


def test_multiplyGF():
    print("Testing multiplyGF...")
    result = utils.multiplyGF(0x57, 0x13)
    expected_result = 0xFE
    if result == expected_result:
        print("Test passed!\n")
    else:
        print("Test failed! Expected:", expected_result, "but got:", result, "\n")


def test_convert_key_in_matrix():
    print("Testing convert_key_in_matrix...")
    key = "5468617473206D79204B756E67204675"
    key_bytes = bytes.fromhex(key)
    result = utils.convert_key_in_matrix(key_bytes, 0)
    expected_result = [
        [0x54, 0x73, 0x20, 0x67],
        [0x68, 0x20, 0x4B, 0x20],
        [0x61, 0x6D, 0x75, 0x46],
        [0x74, 0x79, 0x6E, 0x75]
    ]

    if result == expected_result:
        print("Test passed!\n")
    else:
        print("Test failed! Expected:", expected_result, "but got:", result, "\n")


def test_convert_matrix_in_key():
    print("Testing convert_matrix_in_key...")
    state_matrix = [
        [0x54, 0x73, 0x20, 0x67],
        [0x68, 0x20, 0x4B, 0x20],
        [0x61, 0x6D, 0x75, 0x46],
        [0x74, 0x79, 0x6E, 0x75]
    ]
    result = utils.convert_matrix_in_key(state_matrix)
    expected_result = [0x54, 0x68, 0x61, 0x74, 0x73, 0x20, 0x6D, 0x79, 0x20, 0x4B, 0x75, 0x6E, 0x67, 0x20, 0x46, 0x75]
    if result == expected_result:
        print("Test passed!\n")
    else:
        print("Test failed! Expected:", expected_result, "but got:", result, "\n")


def test_sub_word():
    print("Testing sub_word...")
    result = utils.sub_word(bytes([0x20, 0x46, 0x75, 0x67]))
    expected_result = ([0xB7, 0x5A, 0x9D, 0x85])
    if result == expected_result:
        print("Test passed!\n")
    else:
        print("Test failed! Expected:", expected_result, "but got:", result, "\n")


def test_key_expansion():
    print("Testing key_expansion...")
    key_hex = "5468617473206D79204B756E67204675"
    key_bytes = bytes.fromhex(key_hex)
    expanded_keys = AES.key_expansion(key_bytes)
    expected_keys = [
        "5468617473206D79204B756E67204675",
        "E232FCF191129188B159E4E6D679A293",
        "56082007C71AB18F76435569A03AF7FA",
        "D2600DE7157ABC686339E901C3031EFB",
        "A11202C9B468BEA1D75157A01452495B",
        "B1293B3305418592D210D232C6429B69",
        "BD3DC287B87C47156A6C9527AC2E0E4E",
        "CC96ED1674EAAA031E863F24B2A8316A",
        "8E51EF21FABB4522E43D7A0656954B6C",
        "BFE2BF904559FAB2A16480B4F7F1CBD8",
        "28FDDEF86DA4244ACCC0A4FE3B316F26"
    ]

    for i in range(AESParameters.Nr + 1):
        # Extract the bytes for the current round key (0-16, 16-32 ... )
        round_key_bytes = expanded_keys[
                          AESParameters.nr_key_bytes * i:AESParameters.nr_key_bytes * i + AESParameters.nr_key_bytes]

        # Convert the bytes to hexadecimal string
        round_key_hex = round_key_bytes.hex().upper()

        # Check if the generated round key matches the expected one
        if round_key_hex == expected_keys[i]:
            print(f"Round {i}: Generated round key matches the expected one.")
        else:
            print(f"Round {i}: Generated round key does not match the expected one.")
            print(f"Current: {round_key_hex}")
            print(f"Expected: {expected_keys[i]}")
    print()


def test_add_round_key():
    print("Testing add_round_key...")
    state_matrix = [
        [0x54, 0x4F, 0x4E, 0x20],
        [0x77, 0x6E, 0x69, 0x54],
        [0x6F, 0x65, 0x6E, 0x77],
        [0x20, 0x20, 0x65, 0x6F]
    ]
    round_key_matrix = [
        [0x54, 0x73, 0x20, 0x67],
        [0x68, 0x20, 0x4B, 0x20],
        [0x61, 0x6D, 0x75, 0x46],
        [0x74, 0x79, 0x6E, 0x75]
    ]
    result = utils.add_round_key(state_matrix, round_key_matrix)
    expected_output = [
        [0x00, 0x3C, 0x6E, 0x47],
        [0x1F, 0x4E, 0x22, 0x74],
        [0x0E, 0x08, 0x1B, 0x31],
        [0x54, 0x59, 0x0B, 0x1A]
    ]

    if result == expected_output:
        print("Test passed!\n")
    else:
        print("Test failed! Expected:", expected_output, "but got:", result, "\n")


def test_sub_bytes():
    print("Testing sub_bytes...")
    state_matrix = [
        [0x00, 0x3C, 0x6E, 0x47],
        [0x1F, 0x4E, 0x22, 0x74],
        [0x0E, 0x08, 0x1B, 0x31],
        [0x54, 0x59, 0x0B, 0x1A]
    ]
    result = utils.sub_bytes(state_matrix)
    expected_output = [
        [0x63, 0xEB, 0x9F, 0xA0],
        [0xC0, 0x2F, 0x93, 0x92],
        [0xAB, 0x30, 0xAF, 0xC7],
        [0x20, 0xCB, 0x2B, 0xA2]
    ]

    if result == expected_output:
        print("Test passed!\n")
    else:
        print("Test failed! Expected:", expected_output, "but got:", result, "\n")


def test_shift_rows():
    print("Testing shift_rows...")
    state_matrix = [
        [0x63, 0xEB, 0x9F, 0xA0],
        [0xC0, 0x2F, 0x93, 0x92],
        [0xAB, 0x30, 0xAF, 0xC7],
        [0x20, 0xCB, 0x2B, 0xA2]
    ]

    expected_output = [
        [0x63, 0xEB, 0x9F, 0xA0],
        [0x2F, 0x93, 0x92, 0xC0],
        [0xAF, 0xC7, 0xAB, 0x30],
        [0xA2, 0x20, 0xCB, 0x2B]
    ]

    result = utils.shift_rows(state_matrix)

    if result == expected_output:
        print("Test passed!\n")
    else:
        print("Test failed! Expected:", expected_output, "but got:", result, "\n")


def test_mix_columns():
    print("Testing mix_columns...")
    state_matrix = [
        [0x63, 0xEB, 0x9F, 0xA0],
        [0x2F, 0x93, 0x92, 0xC0],
        [0xAF, 0xC7, 0xAB, 0x30],
        [0xA2, 0x20, 0xCB, 0x2B]
    ]

    expected_output = [
        [0xBA, 0x84, 0xE8, 0x1B],
        [0x75, 0xA4, 0x8D, 0x40],
        [0xF4, 0x8D, 0x06, 0x7D],
        [0x7A, 0x32, 0x0E, 0x5D]
    ]

    result = utils.mix_columns(state_matrix)

    if result == expected_output:
        print("Test passed!\n")
    else:
        print("Test failed! Expected:", expected_output, "but got:", result, "\n")


def test_cypher():
    print("Testing cypher...")
    key = "Thats my Kung Fu"
    key = bytes.fromhex(utils.text_to_hex(key))

    to_be_encrypted = "Two One Nine Two"
    to_be_encrypted = bytes.fromhex(utils.text_to_hex(to_be_encrypted))

    expanded_keys = AES.key_expansion(key)
    result = bytes(AES.cipher(to_be_encrypted, expanded_keys))

    expected_output = bytes.fromhex("29 C3 50 5F 57 14 20 F6 40 22 99 B3 1A 02 D7 3A")

    if result == expected_output:
        print("Test passed!\n")
    else:
        print("Test failed! Expected:", expected_output, "but got:", result, "\n")

    return result, expanded_keys


def test_rot_word():
    print("Testing rot_word...")
    word = [0x01, 0x02, 0x03, 0x04]
    result = utils.rot_word(word)
    expected_output = [0x02, 0x03, 0x04, 0x01]

    if result == expected_output:
        print("Test passed!\n")
    else:
        print("Test failed! Expected:", expected_output, "but got:", result, "\n")


def test_inv_shifted_rows():
    print("Testing inv_shift_rows...")
    state_matrix = [
        [0x63, 0xEB, 0x9F, 0xA0],
        [0x2F, 0x93, 0x92, 0xC0],
        [0xAF, 0xC7, 0xAB, 0x30],
        [0xA2, 0x20, 0xCB, 0x2B]
    ]

    expected_output = [
        [0x63, 0xEB, 0x9F, 0xA0],
        [0xC0, 0x2F, 0x93, 0x92],
        [0xAB, 0x30, 0xAF, 0xC7],
        [0x20, 0xCB, 0x2B, 0xA2]
    ]

    result = utils.inv_shift_rows(state_matrix)

    if result == expected_output:
        print("Test passed!\n")
    else:
        print("Test failed! Expected:", expected_output, "but got:", result, "\n")


def test_inv_sub_bytes():
    print("Testing inv_sub_bytes...")
    state_matrix = [
        [0x00, 0x01, 0x02, 0x03],
        [0x10, 0x11, 0x12, 0x13],
        [0x20, 0x21, 0x22, 0x23],
        [0x30, 0x31, 0x32, 0x33]
    ]

    expected_output = [
        [0x52, 0x09, 0x6A, 0xD5],
        [0x7C, 0xE3, 0x39, 0x82],
        [0x54, 0x7B, 0x94, 0x32],
        [0x08, 0x2E, 0xA1, 0x66]
    ]

    result = utils.inv_sub_bytes(state_matrix)

    if result == expected_output:
        print("Test passed!\n")
    else:
        print("Test failed! Expected:", expected_output, "but got:", result, "\n")


def test_inv_mix_columns():
    print("Testing inv_mix_columns...")
    state_matrix = [
        [0xBA, 0x84, 0xE8, 0x1B],
        [0x75, 0xA4, 0x8D, 0x40],
        [0xF4, 0x8D, 0x06, 0x7D],
        [0x7A, 0x32, 0x0E, 0x5D]
    ]

    expected_output = [
        [0x63, 0xEB, 0x9F, 0xA0],
        [0x2F, 0x93, 0x92, 0xC0],
        [0xAF, 0xC7, 0xAB, 0x30],
        [0xA2, 0x20, 0xCB, 0x2B]
    ]

    result = utils.inv_mix_columns(state_matrix)

    if result == expected_output:
        print("Test passed!\n")
    else:
        print("Test failed! Expected:", expected_output, "but got:", result, "\n")


def test_inv_add_round_key():
    print("Testing inv_add_round_key...")
    state_matrix = [
        [0x00, 0x3C, 0x6E, 0x47],
        [0x1F, 0x4E, 0x22, 0x74],
        [0x0E, 0x08, 0x1B, 0x31],
        [0x54, 0x59, 0x0B, 0x1A]
    ]
    round_key_matrix = [
        [0x54, 0x73, 0x20, 0x67],
        [0x68, 0x20, 0x4B, 0x20],
        [0x61, 0x6D, 0x75, 0x46],
        [0x74, 0x79, 0x6E, 0x75]
    ]
    result = utils.inv_add_round_key(state_matrix, round_key_matrix)
    expected_output = [
        [0x54, 0x4F, 0x4E, 0x20],
        [0x77, 0x6E, 0x69, 0x54],
        [0x6F, 0x65, 0x6E, 0x77],
        [0x20, 0x20, 0x65, 0x6F]
    ]
    if result == expected_output:
        print("Test passed!\n")
    else:
        print("Test failed! Expected:", expected_output, "but got:", result, "\n")


def test_inv_cipher(output, wkey):
    print("Testing inv_cipher...")
    result = bytes(AES.inv_cipher(output, wkey))

    expected_output = "Two One Nine Two"
    expected_output = bytes.fromhex(utils.text_to_hex(expected_output))

    if result == expected_output:
        print("Test passed!\n")
    else:
        print("Test failed! Expected:", expected_output, "but got:", result, "\n")


def test_full_text():
    print("Testing cypher with full text...")
    key = "Thats my Kung Fu"
    key = bytes.fromhex(utils.text_to_hex(key))

    # Open the file for reading
    with open("file.txt", "r") as file:
        to_be_encrypted = file.read()

    result_of_encrypt = bytes(AES.encrypt(to_be_encrypted, key))
    result_of_decrypt = AES.decrypt(result_of_encrypt, key)

    # Check if the text was encrypted and decrypted successfully
    if result_of_decrypt == to_be_encrypted:
        print("Test passed -> Decrypted successfully!\n")
    else:
        print("Test failed! -> Decrypted unsuccessfully! Expected:", to_be_encrypted, "but got:",
              result_of_decrypt.decode(), "\n")


def test_diffie_hellman_key():
    print("Testing diffie_hellman_key...")
    p = 23
    g = 5
    a = 4
    b = 3

    A = pow(g, a, p)
    B = pow(g, b, p)

    sA = pow(B, a, p)
    sB = pow(A, b, p)

    if sA == sB:
        print("Test passed!\n")
    else:
        print("Test failed! Expected:", sA, "but got:", sB, "\n")


if __name__ == "__main__":
    test_multiplyGF()
    test_convert_key_in_matrix()
    test_convert_matrix_in_key()
    test_sub_word()
    test_key_expansion()
    test_add_round_key()
    test_sub_bytes()
    test_shift_rows()
    test_mix_columns()
    test_rot_word()
    result, wkey = test_cypher()

    test_inv_shifted_rows()
    test_inv_sub_bytes()
    test_inv_mix_columns()
    test_inv_add_round_key()
    test_inv_cipher(result, wkey)
    test_full_text()
    test_diffie_hellman_key()
