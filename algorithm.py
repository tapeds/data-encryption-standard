pc1_table = [57, 49, 41, 33, 25, 17, 9,
             1, 58, 50, 42, 34, 26, 18,
             10, 2, 59, 51, 43, 35, 27,
             19, 11, 3, 60, 52, 44, 36,
             63, 55, 47, 39, 31, 23, 15,
             7, 62, 54, 46, 38, 30, 22,
             14, 6, 61, 53, 45, 37, 29,
             21, 13, 5, 28, 20, 12, 4]

pc2_table = [14, 17, 11, 24, 1, 5, 3, 28,
             15, 6, 21, 10, 23, 19, 12, 4,
             26, 8, 16, 7, 27, 20, 13, 2,
             41, 52, 31, 37, 47, 55, 30, 40,
             51, 45, 33, 48, 44, 49, 39, 56,
             34, 53, 46, 42, 50, 36, 29, 32]

shift_positions = [1, 2, 9, 16]

ip_table = [58, 50, 42, 34, 26, 18, 10, 2,
            60, 52, 44, 36, 28, 20, 12, 4,
            62, 54, 46, 38, 30, 22, 14, 6,
            64, 56, 48, 40, 32, 24, 16, 8,
            57, 49, 41, 33, 25, 17, 9, 1,
            59, 51, 43, 35, 27, 19, 11, 3,
            61, 53, 45, 37, 29, 21, 13, 5,
            63, 55, 47, 39, 31, 23, 15, 7]

ip_inv_table = [40, 8, 48, 16, 56, 24, 64, 32,
                39, 7, 47, 15, 55, 23, 63, 31,
                38, 6, 46, 14, 54, 22, 62, 30,
                37, 5, 45, 13, 53, 21, 61, 29,
                36, 4, 44, 12, 52, 20, 60, 28,
                35, 3, 43, 11, 51, 19, 59, 27,
                34, 2, 42, 10, 50, 18, 58, 26,
                33, 1, 41, 9, 49, 17, 57, 25]

expansion_table = [32, 1, 2, 3, 4, 5, 4, 5, 6, 7, 8, 9,
                   8, 9, 10, 11, 12, 13, 12, 13, 14, 15, 16, 17,
                   16, 17, 18, 19, 20, 21, 20, 21, 22, 23, 24, 25,
                   24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32, 1]

p_table = [16, 7, 20, 21, 29, 12, 28, 17,
           1, 15, 23, 26, 5, 18, 31, 10,
           2, 8, 24, 14, 32, 27, 3, 9,
           19, 13, 30, 6, 22, 11, 4, 25]

s_boxes = [
    [[14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
     [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
     [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
     [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]],

    [[15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
     [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
     [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
     [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9]],

    [[10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
     [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
     [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
     [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12]],

]

s_boxes.extend([
    [[7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
     [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
     [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
     [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14]],
    [[2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
     [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
     [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
     [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3]],
    [[12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
     [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
     [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
     [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13]],
    [[4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
     [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
     [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
     [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12]],
    [[13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
     [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
     [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
     [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11]],
])

sub_keys = []

def text_to_bin(text):
    return ''.join(format(ord(c), '08b') for c in text)

def bin_to_text(binary_string):
    length = len(binary_string)
    binary_string = binary_string[:length - (length % 8)]
    chars = [chr(int(binary_string[i:i + 8], 2)) for i in range(0, len(binary_string), 8)]
    return ''.join(chars)

def pc1_conversion(binary_key):
    temp_list = [int(x) for x in binary_key]
    return [temp_list[i - 1] for i in pc1_table]

def shift_left(bits, shift_value):
    return bits[shift_value:] + bits[:shift_value]

def generate_subkeys(left, right):
    for round_count in range(1, 17):
        shift_value = 1 if round_count in shift_positions else 2
        left = shift_left(left, shift_value)
        right = shift_left(right, shift_value)
        merged_bits = left + right
        sub_key = [merged_bits[i - 1] for i in pc2_table]
        sub_keys.append(sub_key)

def key_setup():
    key = input("Enter key (8 characters): ")
    if len(key) != 8:
        print("Key must be exactly 8 characters long.")
        exit()
    binary_key = text_to_bin(key)
    initial_key = pc1_conversion(binary_key)
    left_bits = initial_key[:28]
    right_bits = initial_key[28:]
    generate_subkeys(left_bits, right_bits)

def initial_permutation(bits):
    return [int(bits[i - 1]) for i in ip_table]

def expansion_box(right_half):
    return [right_half[i - 1] for i in expansion_table]

def xor_with_key(expanded, key_index):
    return [expanded[i] ^ sub_keys[key_index][i] for i in range(len(expanded))]

def s_box_substitution(bits):
    result = ''
    for i in range(8):
        block = bits[i * 6:(i + 1) * 6]
        row = int(f"{block[0]}{block[5]}", 2)
        col = int(''.join(map(str, block[1:5])), 2)
        val = s_boxes[i][row][col]
        bin_val = format(val, '04b')
        result += bin_val
    return [int(bit) for bit in result]

def permutation(sbox_output):
    return [sbox_output[i - 1] for i in p_table]

def des_round(left, right, round_number):
    expanded_right = expansion_box(right)
    xor_result = xor_with_key(expanded_right, round_number)
    sbox_output = s_box_substitution(xor_result)
    p_result = permutation(sbox_output)
    new_right = [left[i] ^ p_result[i] for i in range(len(left))]
    return right, new_right

def final_permutation(bits):
    return [bits[i - 1] for i in ip_inv_table]

def des_encrypt(plaintext):
    binary_plaintext = text_to_bin(plaintext)

    if len(binary_plaintext) < 64:
        binary_plaintext = binary_plaintext.ljust(64, '0')
    else:
        binary_plaintext = binary_plaintext[:64]
    permuted_bits = initial_permutation(binary_plaintext)
    left_half = permuted_bits[:32]
    right_half = permuted_bits[32:]

    for round_number in range(16):
        left_half, right_half = des_round(left_half, right_half, round_number)

    final_bits = right_half + left_half
    final_permuted_bits = final_permutation(final_bits)
    binary_result = ''.join(map(str, final_permuted_bits))

    hex_result = hex(int(binary_result, 2))[2:].upper().zfill(16)
    return hex_result

def des_decrypt(ciphertext):
    binary_ciphertext = bin(int(ciphertext, 16))[2:].zfill(64)
    permuted_bits = initial_permutation(binary_ciphertext)
    left_half = permuted_bits[:32]
    right_half = permuted_bits[32:]

    for round_number in reversed(range(16)):
        left_half, right_half = des_round(left_half, right_half, round_number)

    final_bits = right_half + left_half
    final_permuted_bits = final_permutation(final_bits)
    binary_result = ''.join(map(str, final_permuted_bits))
    plaintext = bin_to_text(binary_result)
    return plaintext.strip('\x00')  

def main():
    key_setup()

    mode = input("Encrypt or Decrypt (e/d)? ").lower()
    if mode == 'e':
        plaintext = input("Enter plaintext (max 8 characters): ")
        if len(plaintext) > 8:
            print("Plaintext must be at most 8 characters.")
            exit()
        ciphertext = des_encrypt(plaintext)
        print(f"Encrypted ciphertext (hex): {ciphertext}")
    elif mode == 'd':
        ciphertext = input("Enter ciphertext (16 hex digits): ")
        if len(ciphertext) != 16:
            print("Ciphertext must be exactly 16 hex digits.")
            exit()
        plaintext = des_decrypt(ciphertext)
        print(f"Decrypted plaintext: {plaintext}")
    else:
        print("Invalid mode, choose 'e' for encrypt or 'd' for decrypt")

if __name__ == "__main__":
    main()
