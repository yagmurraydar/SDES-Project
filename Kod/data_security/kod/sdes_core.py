"""
Core S-DES module.

Step 3.1 includes:
- explicit algorithm constants
- input validation
- low-level bit helper functions

Step 3.2 adds:
- P10/P8 permutation wrappers
- S-DES key generation with full trace output

Step 3.3 adds:
- EP/P4 permutation wrappers
- S-box lookup and combined S-box processing
- one-round fk() function with full trace output

Step 3.4 adds:
- IP/IP inverse permutation wrappers
- SW half-switch function
- full S-DES encryption with structured trace output

Step 3.5 adds:
- full S-DES decryption with reversed subkeys and structured trace output

ECB mode adds:
- multi-block encryption/decryption by applying S-DES independently to each block

CBC mode adds:
- multi-block encryption/decryption with XOR chaining and an 8-bit IV

OFB mode adds:
- multi-block encryption/decryption with S-DES-generated keystream blocks

Attack utilities add:
- known-plaintext brute-force key search
"""

import time

# ---------------------------------------------------------------------------
# S-DES permutation tables and S-boxes
# ---------------------------------------------------------------------------

# Permutation tables are defined using 1-based indexing, as in standard
# S-DES notation. The permute() helper converts them to 0-based indexing.
P10_TABLE = [3, 5, 2, 7, 4, 10, 1, 9, 8, 6]
P8_TABLE = [6, 3, 7, 4, 8, 5, 10, 9]
P4_TABLE = [2, 4, 3, 1]

IP_TABLE = [2, 6, 3, 1, 4, 8, 5, 7]
IP_INV_TABLE = [4, 1, 3, 5, 7, 2, 8, 6]

EP_TABLE = [4, 1, 2, 3, 2, 3, 4, 1]

S0 = [
    [1, 0, 3, 2],
    [3, 2, 1, 0],
    [0, 2, 1, 3],
    [3, 1, 3, 2],
]

S1 = [
    [0, 1, 2, 3],
    [2, 0, 1, 3],
    [3, 0, 1, 0],
    [2, 1, 0, 3],
]


# ---------------------------------------------------------------------------
# Validation helpers
# ---------------------------------------------------------------------------

def validate_binary_string(bits, expected_length, label):
    """
    Validate that a value is a fixed-length binary string.

    Args:
        bits: Candidate bit string.
        expected_length: Required number of bits.
        label: Human-readable field name for error messages.

    Raises:
        TypeError: If bits is not a string.
        ValueError: If length is wrong or non-binary characters are present.
    """
    if not isinstance(bits, str):
        raise TypeError(f"{label} must be {expected_length}-bit binary string.")

    if len(bits) != expected_length:
        raise ValueError(
            f"{label} must be {expected_length}-bit binary string "
            f"(got length {len(bits)}: '{bits}')."
        )

    invalid_chars = sorted(set(bits) - {"0", "1"})
    if invalid_chars:
        raise ValueError(
            f"{label} must be {expected_length}-bit binary string "
            f"(invalid character(s): {', '.join(repr(ch) for ch in invalid_chars)})."
        )


def validate_10bit_key(key):
    """Validate a 10-bit S-DES key."""
    validate_binary_string(key, 10, "Key")


def validate_8bit_block(block):
    """Validate an 8-bit S-DES plaintext/ciphertext block."""
    validate_binary_string(block, 8, "Block")


def validate_iv(iv_8bit):
    """Validate an 8-bit initialization vector for block cipher modes."""
    validate_binary_string(iv_8bit, 8, "IV")


def validate_block_list(blocks):
    """Validate a non-empty list of 8-bit binary blocks."""
    if not isinstance(blocks, list):
        raise TypeError("Blocks must be provided as a list of 8-bit binary strings.")

    if not blocks:
        raise ValueError("Blocks list must contain at least one 8-bit binary string.")

    for index, block in enumerate(blocks):
        validate_binary_string(block, 8, f"Block at index {index}")


def parse_blocks_input(input_string):
    """
    Parse a space-separated string of 8-bit binary blocks.

    Example:
        parse_blocks_input("11010111 01000001 10101010")
        -> ["11010111", "01000001", "10101010"]
    """
    if not isinstance(input_string, str):
        raise TypeError("Blocks input must be a string.")

    blocks = input_string.strip().split()
    validate_block_list(blocks)
    return blocks


def parse_input(value, format_type):
    """
    Convert one user input value into an 8-bit binary block.

    Supported format_type values:
        - "binary": value must already be an 8-bit binary string
        - "decimal": value must be an integer string in range 0..255
        - "ascii": value must be exactly one 8-bit character
    """
    if not isinstance(format_type, str):
        raise TypeError("Format type must be one of: binary, decimal, ascii.")

    normalized_format = format_type.strip().lower()

    if normalized_format == "binary":
        validate_8bit_block(value)
        return value

    if normalized_format == "decimal":
        try:
            decimal_value = int(str(value).strip())
        except ValueError as exc:
            raise ValueError("Invalid decimal input (must be an integer from 0 to 255).") from exc

        if decimal_value < 0 or decimal_value > 255:
            raise ValueError("Invalid decimal input (must be in range 0 to 255).")

        return format(decimal_value, "08b")

    if normalized_format == "ascii":
        if not isinstance(value, str) or len(value) != 1:
            raise ValueError("Invalid ASCII input (must be 1 character).")

        decimal_value = ord(value)
        if decimal_value > 255:
            raise ValueError("Invalid ASCII input (character must fit in 8 bits).")

        return format(decimal_value, "08b")

    raise ValueError("Format type must be one of: binary, decimal, ascii.")


def format_output(bits):
    """
    Return binary, decimal, and printable ASCII representations of an 8-bit block.
    """
    validate_8bit_block(bits)
    decimal_value = int(bits, 2)
    ascii_value = chr(decimal_value) if 32 <= decimal_value <= 126 else "Not printable"
    return {
        "binary": bits,
        "decimal": decimal_value,
        "ascii": ascii_value,
    }


# ---------------------------------------------------------------------------
# Low-level bit helper functions
# ---------------------------------------------------------------------------

def permute(bits, table):
    """
    Rearrange bits according to a 1-based permutation table.

    Example:
        bits = "10110010"
        table = [2, 6, 3, 1]
        result = "0101"

    Note:
        Table entries follow the academic S-DES convention (1-based indexing),
        so each position p is read from bits[p - 1] in Python.
    """
    return "".join(bits[position - 1] for position in table)


def left_shift(bits, n):
    """
    Perform a circular left shift by n positions.

    Example:
        left_shift("10101", 1) -> "01011"
        left_shift("10101", 2) -> "10110"
    """
    if not isinstance(bits, str):
        raise TypeError("bits must be a string.")
    if len(bits) == 0:
        raise ValueError("bits must not be empty.")
    if not isinstance(n, int):
        raise TypeError("n must be an integer.")

    shift_amount = n % len(bits)
    return bits[shift_amount:] + bits[:shift_amount]


def xor_bits(a, b):
    """
    Compute bitwise XOR of two equal-length binary strings.

    Example:
        xor_bits("1010", "1100") -> "0110"
    """
    if not isinstance(a, str) or not isinstance(b, str):
        raise TypeError("Both XOR operands must be strings.")
    if len(a) != len(b):
        raise ValueError(
            f"XOR operands must have the same length, but got {len(a)} and {len(b)}."
        )

    invalid_a = set(a) - {"0", "1"}
    invalid_b = set(b) - {"0", "1"}
    if invalid_a or invalid_b:
        raise ValueError("XOR operands must contain only binary digits 0 or 1.")

    return "".join("0" if bit_a == bit_b else "1" for bit_a, bit_b in zip(a, b))


def split_bits(bits, size):
    """
    Split a bit string into left and right parts, where the left part has length size.

    Example:
        split_bits("10101100", 4) -> ("1010", "1100")
        split_bits("1100011010", 5) -> ("11000", "11010")
    """
    if not isinstance(bits, str):
        raise TypeError("bits must be a string.")
    if not isinstance(size, int):
        raise TypeError("size must be an integer.")
    if size < 0 or size > len(bits):
        raise ValueError(
            f"size must be between 0 and {len(bits)}, but got {size}."
        )

    return bits[:size], bits[size:]


def join_bits(left, right):
    """
    Concatenate left and right bit strings.

    Example:
        join_bits("1010", "1100") -> "10101100"
    """
    if not isinstance(left, str) or not isinstance(right, str):
        raise TypeError("left and right must be strings.")

    return left + right


# ---------------------------------------------------------------------------
# Key scheduling functions
# ---------------------------------------------------------------------------

def apply_p10(key_10bit):
    """
    Apply the P10 permutation to a validated 10-bit key.

    Example:
        apply_p10("1010000010") -> "1000001100"
    """
    validate_10bit_key(key_10bit)
    return permute(key_10bit, P10_TABLE)


def apply_p8(bits_10bit):
    """
    Apply the P8 permutation to a 10-bit intermediate key state.

    Example:
        apply_p8("0000111000") -> "10100100"
    """
    validate_binary_string(bits_10bit, 10, "P8 input")
    return permute(bits_10bit, P8_TABLE)


def generate_subkeys(key_10bit, verbose=False):
    """
    Generate the two 8-bit S-DES subkeys K1 and K2.

    Exact flow:
        validate_10bit_key
        -> P10
        -> split into left/right 5-bit halves
        -> LS-1 on both halves
        -> join halves
        -> P8 => K1
        -> LS-2 on the already LS-1 shifted halves
        -> join halves
        -> P8 => K2

    Args:
        key_10bit: 10-bit master key.
        verbose: If True, include all intermediate key-schedule states in trace.

    Returns:
        A tuple (K1, K2, trace), where K1 and K2 are 8-bit binary strings and
        trace is a dictionary. When verbose=False, trace is an empty dictionary.
    """
    validate_10bit_key(key_10bit)

    after_p10 = apply_p10(key_10bit)
    left_p10, right_p10 = split_bits(after_p10, 5)

    after_ls1_left = left_shift(left_p10, 1)
    after_ls1_right = left_shift(right_p10, 1)
    joined_ls1 = join_bits(after_ls1_left, after_ls1_right)
    k1 = apply_p8(joined_ls1)

    after_ls2_left = left_shift(after_ls1_left, 2)
    after_ls2_right = left_shift(after_ls1_right, 2)
    joined_ls2 = join_bits(after_ls2_left, after_ls2_right)
    k2 = apply_p8(joined_ls2)

    trace = {}
    if verbose:
        trace = {
            "original_key": key_10bit,
            "after_p10": after_p10,
            "left_p10": left_p10,
            "right_p10": right_p10,
            "after_ls1_left": after_ls1_left,
            "after_ls1_right": after_ls1_right,
            "K1": k1,
            "after_ls2_left": after_ls2_left,
            "after_ls2_right": after_ls2_right,
            "K2": k2,
        }

    return k1, k2, trace


# ---------------------------------------------------------------------------
# Round function and S-box helpers
# ---------------------------------------------------------------------------

def apply_ep(right_4bit):
    """
    Apply expansion/permutation EP to a 4-bit right half.

    Example:
        apply_ep("1100") -> "01101001"
    """
    validate_binary_string(right_4bit, 4, "EP input")
    return permute(right_4bit, EP_TABLE)


def apply_p4(bits_4bit):
    """
    Apply the P4 permutation to a 4-bit S-box output.

    Example:
        apply_p4("1001") -> "0101"
    """
    validate_binary_string(bits_4bit, 4, "P4 input")
    return permute(bits_4bit, P4_TABLE)


def sbox_lookup(bits_4bit, sbox):
    """
    Look up a 4-bit input in one S-box and return a 2-bit binary string.

    Indexing rule:
        For input b1 b2 b3 b4:
        - row = b1b4 (first and last bit)
        - column = b2b3 (middle two bits)

    Example:
        bits_4bit = "1011"
        row = "11" -> 3
        column = "01" -> 1
    """
    validate_binary_string(bits_4bit, 4, "S-box input")

    if not isinstance(sbox, list) or len(sbox) != 4 or any(len(row) != 4 for row in sbox):
        raise ValueError("sbox must be a 4x4 table.")

    row_bits = bits_4bit[0] + bits_4bit[3]
    col_bits = bits_4bit[1] + bits_4bit[2]
    row_index = int(row_bits, 2)
    col_index = int(col_bits, 2)
    value = sbox[row_index][col_index]

    return format(value, "02b")


def apply_sboxes(bits_8bit, verbose=False):
    """
    Apply S0 to the left 4 bits and S1 to the right 4 bits, then combine outputs.

    Returns:
        (combined_output, trace)

        combined_output is a 4-bit binary string.
        trace contains S-box input/output details when verbose=True,
        otherwise it is an empty dictionary.
    """
    validate_binary_string(bits_8bit, 8, "S-box stage input")

    s0_input, s1_input = split_bits(bits_8bit, 4)
    s0_output = sbox_lookup(s0_input, S0)
    s1_output = sbox_lookup(s1_input, S1)
    combined_output = join_bits(s0_output, s1_output)

    trace = {}
    if verbose:
        trace = {
            "S0_input": s0_input,
            "S0_output": s0_output,
            "S1_input": s1_input,
            "S1_output": s1_output,
            "combined_sbox_output": combined_output,
        }

    return combined_output, trace


def fk(block_8bit, subkey_8bit, verbose=False):
    """
    Apply one S-DES round function.

    Flow:
        split block into L and R
        -> EP(R)
        -> XOR with subkey
        -> S-boxes
        -> P4
        -> L XOR P4_output
        -> return new_left || original_right

    Important:
        The right half R is not modified inside fk().

    Returns:
        (final_block, trace)

        final_block = new_left || original_right
        trace contains all required round internals when verbose=True,
        otherwise it is an empty dictionary.
    """
    validate_8bit_block(block_8bit)
    validate_binary_string(subkey_8bit, 8, "S-DES subkey")

    left, right = split_bits(block_8bit, 4)
    ep_right = apply_ep(right)
    xor_with_subkey = xor_bits(ep_right, subkey_8bit)
    combined_sbox_output, sbox_trace = apply_sboxes(xor_with_subkey, verbose=True)
    p4_output = apply_p4(combined_sbox_output)
    left_xor_p4 = xor_bits(left, p4_output)
    final_block = join_bits(left_xor_p4, right)

    trace = {}
    if verbose:
        trace = {
            "L": left,
            "R": right,
            "EP_R": ep_right,
            "xor_with_subkey": xor_with_subkey,
            "S0_input": sbox_trace["S0_input"],
            "S0_output": sbox_trace["S0_output"],
            "S1_input": sbox_trace["S1_input"],
            "S1_output": sbox_trace["S1_output"],
            "combined_sbox_output": combined_sbox_output,
            "P4_output": p4_output,
            "L_xor_P4": left_xor_p4,
            "final_block": final_block,
        }

    return final_block, trace


# ---------------------------------------------------------------------------
# Full-block permutation wrappers and encryption
# ---------------------------------------------------------------------------

def apply_ip(block_8bit):
    """
    Apply the initial permutation IP to an 8-bit block.

    Example:
        apply_ip("11010111") -> "11111010"
    """
    validate_8bit_block(block_8bit)
    return permute(block_8bit, IP_TABLE)


def apply_ip_inverse(block_8bit):
    """
    Apply the inverse initial permutation IP^-1 to an 8-bit block.

    Example:
        apply_ip_inverse("11111010") -> "11010111"
    """
    validate_8bit_block(block_8bit)
    return permute(block_8bit, IP_INV_TABLE)


def switch_halves(block_8bit):
    """
    Swap the left and right 4-bit halves of an 8-bit block.

    Example:
        switch_halves("10101100") -> "11001010"
    """
    validate_8bit_block(block_8bit)
    left, right = split_bits(block_8bit, 4)
    return join_bits(right, left)


def encrypt_block(plaintext_8bit, key_10bit, verbose=False):
    """
    Encrypt one 8-bit plaintext block using S-DES.

    Exact flow:
        validate plaintext and key
        -> generate K1, K2
        -> IP
        -> fk(..., K1)
        -> SW
        -> fk(..., K2)
        -> IP^-1

    Returns:
        If verbose=False:
            ciphertext_8bit
        If verbose=True:
            (ciphertext_8bit, trace)
    """
    validate_8bit_block(plaintext_8bit)
    validate_10bit_key(key_10bit)

    k1, k2, _ = generate_subkeys(key_10bit, verbose=False)

    after_ip = apply_ip(plaintext_8bit)
    after_fk1, round1_trace = fk(after_ip, k1, verbose=True)
    after_sw = switch_halves(after_fk1)
    after_fk2, round2_trace = fk(after_sw, k2, verbose=True)
    ciphertext_8bit = apply_ip_inverse(after_fk2)

    if not verbose:
        return ciphertext_8bit

    trace = {
        "type": "encryption",
        "blocks": [
            {
                "block_index": 0,
                "input_block": plaintext_8bit,
                "output_block": ciphertext_8bit,
            }
        ],
        "steps": {
            "subkeys": {
                "K1": k1,
                "K2": k2,
            },
            "after_ip": after_ip,
            "round1_fk": round1_trace,
            "after_sw": after_sw,
            "round2_fk": round2_trace,
            "after_ip_inverse": ciphertext_8bit,
        },
        "subkeys": {
            "K1": k1,
            "K2": k2,
        },
        "after_ip": after_ip,
        "round1_fk": round1_trace,
        "after_sw": after_sw,
        "round2_fk": round2_trace,
        "after_ip_inverse": ciphertext_8bit,
    }

    return ciphertext_8bit, trace


def decrypt_block(ciphertext_8bit, key_10bit, verbose=False):
    """
    Decrypt one 8-bit ciphertext block using S-DES.

    Exact flow:
        validate ciphertext and key
        -> generate K1, K2
        -> IP
        -> fk(..., K2)
        -> SW
        -> fk(..., K1)
        -> IP^-1

    Returns:
        If verbose=False:
            plaintext_8bit
        If verbose=True:
            (plaintext_8bit, trace)
    """
    validate_8bit_block(ciphertext_8bit)
    validate_10bit_key(key_10bit)

    k1, k2, _ = generate_subkeys(key_10bit, verbose=False)

    after_ip = apply_ip(ciphertext_8bit)
    after_fk1, round1_trace = fk(after_ip, k2, verbose=True)
    after_sw = switch_halves(after_fk1)
    after_fk2, round2_trace = fk(after_sw, k1, verbose=True)
    plaintext_8bit = apply_ip_inverse(after_fk2)

    if not verbose:
        return plaintext_8bit

    trace = {
        "type": "decryption",
        "blocks": [
            {
                "block_index": 0,
                "input_block": ciphertext_8bit,
                "output_block": plaintext_8bit,
            }
        ],
        "steps": {
            "subkeys": {
                "K1": k1,
                "K2": k2,
            },
            "after_ip": after_ip,
            "round1_fk": round1_trace,
            "after_sw": after_sw,
            "round2_fk": round2_trace,
            "after_ip_inverse": plaintext_8bit,
        },
        "subkeys": {
            "K1": k1,
            "K2": k2,
        },
        "after_ip": after_ip,
        "round1_fk": round1_trace,
        "after_sw": after_sw,
        "round2_fk": round2_trace,
        "after_ip_inverse": plaintext_8bit,
    }

    return plaintext_8bit, trace


# ---------------------------------------------------------------------------
# ECB mode
# ---------------------------------------------------------------------------

def ecb_encrypt(blocks, key_10bit, verbose=False):
    """
    Encrypt multiple 8-bit blocks using Electronic Codebook (ECB) mode.

    Each block is encrypted independently with the same 10-bit key, and the
    output block order matches the input block order.

    Returns:
        If verbose=False:
            list of ciphertext blocks
        If verbose=True:
            (list of ciphertext blocks, trace)
    """
    validate_block_list(blocks)
    validate_10bit_key(key_10bit)

    output_blocks = []
    block_steps = []

    for index, block in enumerate(blocks):
        if verbose:
            output_block, block_trace = encrypt_block(block, key_10bit, verbose=True)
            block_steps.append(
                {
                    "block_index": index,
                    "input_block": block,
                    "output_block": output_block,
                    "block_trace": block_trace,
                }
            )
        else:
            output_block = encrypt_block(block, key_10bit, verbose=False)

        output_blocks.append(output_block)

    if not verbose:
        return output_blocks

    trace = {
        "type": "ecb_encryption",
        "blocks": output_blocks,
        "steps": {
            "blocks": block_steps,
        },
    }
    return output_blocks, trace


def ecb_decrypt(blocks, key_10bit, verbose=False):
    """
    Decrypt multiple 8-bit blocks using Electronic Codebook (ECB) mode.

    Each ciphertext block is decrypted independently with the same 10-bit key,
    and the output block order matches the input block order.

    Returns:
        If verbose=False:
            list of plaintext blocks
        If verbose=True:
            (list of plaintext blocks, trace)
    """
    validate_block_list(blocks)
    validate_10bit_key(key_10bit)

    output_blocks = []
    block_steps = []

    for index, block in enumerate(blocks):
        if verbose:
            output_block, block_trace = decrypt_block(block, key_10bit, verbose=True)
            block_steps.append(
                {
                    "block_index": index,
                    "input_block": block,
                    "output_block": output_block,
                    "block_trace": block_trace,
                }
            )
        else:
            output_block = decrypt_block(block, key_10bit, verbose=False)

        output_blocks.append(output_block)

    if not verbose:
        return output_blocks

    trace = {
        "type": "ecb_decryption",
        "blocks": output_blocks,
        "steps": {
            "blocks": block_steps,
        },
    }
    return output_blocks, trace


# ---------------------------------------------------------------------------
# CBC mode
# ---------------------------------------------------------------------------

def cbc_encrypt(blocks, key_10bit, iv_8bit, verbose=False):
    """
    Encrypt multiple 8-bit blocks using Cipher Block Chaining (CBC) mode.

    For each plaintext block:
        xor_result = plaintext_block XOR previous_ciphertext
        ciphertext_block = encrypt_block(xor_result, key)

    The first previous_ciphertext value is the IV.

    Returns:
        If verbose=False:
            list of ciphertext blocks
        If verbose=True:
            (list of ciphertext blocks, trace)
    """
    validate_block_list(blocks)
    validate_10bit_key(key_10bit)
    validate_iv(iv_8bit)

    output_blocks = []
    block_steps = []
    chaining_value = iv_8bit

    for index, block in enumerate(blocks):
        xor_result = xor_bits(block, chaining_value)
        output_block = encrypt_block(xor_result, key_10bit, verbose=False)
        output_blocks.append(output_block)

        if verbose:
            block_steps.append(
                {
                    "block_index": index,
                    "input_block": block,
                    "chaining_value": chaining_value,
                    "xor_result": xor_result,
                    "output_block": output_block,
                }
            )

        chaining_value = output_block

    if not verbose:
        return output_blocks

    trace = {
        "type": "cbc_encryption",
        "blocks": output_blocks,
        "steps": {
            "iv": iv_8bit,
            "blocks": block_steps,
        },
    }
    return output_blocks, trace


def cbc_decrypt(blocks, key_10bit, iv_8bit, verbose=False):
    """
    Decrypt multiple 8-bit blocks using Cipher Block Chaining (CBC) mode.

    For each ciphertext block:
        decrypted_before_xor = decrypt_block(ciphertext_block, key)
        plaintext_block = decrypted_before_xor XOR previous_ciphertext

    The first previous_ciphertext value is the IV. Chaining always uses the
    original ciphertext block, not the recovered plaintext block.

    Returns:
        If verbose=False:
            list of plaintext blocks
        If verbose=True:
            (list of plaintext blocks, trace)
    """
    validate_block_list(blocks)
    validate_10bit_key(key_10bit)
    validate_iv(iv_8bit)

    output_blocks = []
    block_steps = []
    chaining_value = iv_8bit

    for index, block in enumerate(blocks):
        decrypted_before_xor = decrypt_block(block, key_10bit, verbose=False)
        recovered_block = xor_bits(decrypted_before_xor, chaining_value)
        output_blocks.append(recovered_block)

        if verbose:
            block_steps.append(
                {
                    "block_index": index,
                    "input_block": block,
                    "decrypted_before_xor": decrypted_before_xor,
                    "chaining_value": chaining_value,
                    "recovered_block": recovered_block,
                }
            )

        chaining_value = block

    if not verbose:
        return output_blocks

    trace = {
        "type": "cbc_decryption",
        "blocks": output_blocks,
        "steps": {
            "iv": iv_8bit,
            "blocks": block_steps,
        },
    }
    return output_blocks, trace


# ---------------------------------------------------------------------------
# OFB mode
# ---------------------------------------------------------------------------

def ofb_encrypt(blocks, key_10bit, iv_8bit, verbose=False):
    """
    Encrypt multiple 8-bit blocks using Output Feedback (OFB) mode.

    For each block:
        keystream_block = encrypt_block(feedback_value, key)
        output_block = input_block XOR keystream_block
        feedback_value = keystream_block

    OFB uses encryption to generate the keystream for both encryption and
    decryption.

    Returns:
        If verbose=False:
            list of output blocks
        If verbose=True:
            (list of output blocks, trace)
    """
    validate_block_list(blocks)
    validate_10bit_key(key_10bit)
    validate_iv(iv_8bit)

    output_blocks = []
    block_steps = []
    feedback_value = iv_8bit

    for index, block in enumerate(blocks):
        if verbose:
            keystream_block, encrypt_trace = encrypt_block(
                feedback_value, key_10bit, verbose=True
            )
        else:
            keystream_block = encrypt_block(feedback_value, key_10bit, verbose=False)
            encrypt_trace = None

        output_block = xor_bits(block, keystream_block)
        output_blocks.append(output_block)

        if verbose:
            block_steps.append(
                {
                    "block_index": index,
                    "input_block": block,
                    "feedback_value": feedback_value,
                    "keystream_block": keystream_block,
                    "output_block": output_block,
                    "encrypt_trace": encrypt_trace,
                }
            )

        feedback_value = keystream_block

    if not verbose:
        return output_blocks

    trace = {
        "type": "ofb_encryption",
        "blocks": output_blocks,
        "steps": {
            "iv": iv_8bit,
            "blocks": block_steps,
        },
    }
    return output_blocks, trace


def ofb_decrypt(blocks, key_10bit, iv_8bit, verbose=False):
    """
    Decrypt multiple 8-bit blocks using Output Feedback (OFB) mode.

    OFB decryption uses the same keystream-generation process as encryption:
        keystream_block = encrypt_block(feedback_value, key)
        output_block = input_block XOR keystream_block
        feedback_value = keystream_block

    Returns:
        If verbose=False:
            list of output blocks
        If verbose=True:
            (list of output blocks, trace)
    """
    if not verbose:
        return ofb_encrypt(blocks, key_10bit, iv_8bit, verbose=False)

    output_blocks, trace = ofb_encrypt(blocks, key_10bit, iv_8bit, verbose=True)
    trace["type"] = "ofb_decryption"
    return output_blocks, trace


# ---------------------------------------------------------------------------
# Attack utilities
# ---------------------------------------------------------------------------

def brute_force_attack(plaintext_8bit, ciphertext_8bit, verbose=False):
    """
    Recover candidate S-DES keys from one known plaintext/ciphertext pair.

    The attack tries every possible 10-bit key:
        0000000000 through 1111111111

    Returns:
        If verbose=False:
            {
                "matching_keys": [...],
                "total_tested_keys": 1024,
                "elapsed_time": seconds
            }

        If verbose=True:
            same summary plus a "trace" field containing:
                - tested_key_count
                - first_tested_keys
                - matching_keys
    """
    validate_8bit_block(plaintext_8bit)
    validate_8bit_block(ciphertext_8bit)

    matching_keys = []
    first_tested_keys = []
    start_time = time.perf_counter()

    for key_value in range(1024):
        candidate_key = format(key_value, "010b")

        if verbose and len(first_tested_keys) < 10:
            first_tested_keys.append(candidate_key)

        produced_ciphertext = encrypt_block(plaintext_8bit, candidate_key)
        if produced_ciphertext == ciphertext_8bit:
            matching_keys.append(candidate_key)

    elapsed_time = time.perf_counter() - start_time

    result = {
        "matching_keys": matching_keys,
        "total_tested_keys": 1024,
        "elapsed_time": elapsed_time,
    }

    if verbose:
        result["trace"] = {
            "tested_key_count": 1024,
            "first_tested_keys": first_tested_keys,
            "matching_keys": matching_keys,
        }

    return result


def brute_force_attack_unique(plaintext_8bit, ciphertext_8bit, verbose=False):
    """
    Return only a provably unique brute-force match for one plaintext/ciphertext pair.

    Notes:
        A single S-DES plaintext/ciphertext pair does not always identify a unique key.
        This helper therefore returns the unique key only when exactly one candidate
        survives exhaustive search. When multiple candidates exist, the result is
        marked as ambiguous instead of reporting false-positive keys as final.
    """
    result = brute_force_attack(plaintext_8bit, ciphertext_8bit, verbose=verbose)
    matching_keys = result["matching_keys"]
    unique_key = matching_keys[0] if len(matching_keys) == 1 else None
    result["unique_key"] = unique_key
    result["is_unique_match"] = unique_key is not None
    result["ambiguity_reason"] = None if unique_key is not None else (
        "No unique key can be proven from the provided plaintext/ciphertext pair."
    )
    return result




# ---------------------------------------------------------------------------
# Differential cryptanalysis helpers
# ---------------------------------------------------------------------------

def differential_pair_analysis(plaintext_8bit, input_difference_8bit, key_10bit, verbose=False):
    """
    Analyze one plaintext pair under a fixed input XOR difference.

    Given plaintext P and input difference ΔP, this helper constructs:
        P' = P XOR ΔP
        C  = E_K(P)
        C' = E_K(P')
        ΔC = C XOR C'

    Returns a dictionary containing the plaintext pair, ciphertext pair,
    input/output differences, and optional round traces when verbose=True.
    """
    validate_8bit_block(plaintext_8bit)
    validate_8bit_block(input_difference_8bit)
    validate_10bit_key(key_10bit)

    paired_plaintext = xor_bits(plaintext_8bit, input_difference_8bit)

    if verbose:
        ciphertext_1, trace_1 = encrypt_block(plaintext_8bit, key_10bit, verbose=True)
        ciphertext_2, trace_2 = encrypt_block(paired_plaintext, key_10bit, verbose=True)
    else:
        ciphertext_1 = encrypt_block(plaintext_8bit, key_10bit, verbose=False)
        ciphertext_2 = encrypt_block(paired_plaintext, key_10bit, verbose=False)
        trace_1 = None
        trace_2 = None

    output_difference = xor_bits(ciphertext_1, ciphertext_2)

    result = {
        "plaintext_1": plaintext_8bit,
        "plaintext_2": paired_plaintext,
        "input_difference": input_difference_8bit,
        "ciphertext_1": ciphertext_1,
        "ciphertext_2": ciphertext_2,
        "output_difference": output_difference,
    }

    if verbose:
        result["trace"] = {
            "encryption_1": trace_1,
            "encryption_2": trace_2,
        }

    return result


def differential_experiment(input_difference_8bit, key_10bit, sample_limit=256):
    """
    Run a frequency experiment for one fixed plaintext difference.

    For each plaintext P in the first ``sample_limit`` 8-bit values, this helper
    constructs P' = P XOR ΔP, encrypts both under the same key, and records the
    observed output difference ΔC. The result is useful for demonstrating that
    some output differences appear more frequently than others.
    """
    validate_8bit_block(input_difference_8bit)
    validate_10bit_key(key_10bit)

    if not isinstance(sample_limit, int):
        raise TypeError("sample_limit must be an integer.")
    if sample_limit < 1 or sample_limit > 256:
        raise ValueError("sample_limit must be in range 1 to 256.")

    difference_counts = {}
    pair_results = []

    for value in range(sample_limit):
        plaintext_1 = format(value, "08b")
        plaintext_2 = xor_bits(plaintext_1, input_difference_8bit)
        ciphertext_1 = encrypt_block(plaintext_1, key_10bit, verbose=False)
        ciphertext_2 = encrypt_block(plaintext_2, key_10bit, verbose=False)
        output_difference = xor_bits(ciphertext_1, ciphertext_2)

        difference_counts[output_difference] = difference_counts.get(output_difference, 0) + 1
        pair_results.append(
            {
                "pair_index": value,
                "plaintext_1": plaintext_1,
                "plaintext_2": plaintext_2,
                "input_difference": input_difference_8bit,
                "ciphertext_1": ciphertext_1,
                "ciphertext_2": ciphertext_2,
                "output_difference": output_difference,
            }
        )

    frequency_table = [
        {"output_difference": diff, "count": count}
        for diff, count in sorted(
            difference_counts.items(), key=lambda item: (-item[1], item[0])
        )
    ]

    most_common_output_difference = frequency_table[0]["output_difference"]
    most_common_count = frequency_table[0]["count"]

    return {
        "input_difference": input_difference_8bit,
        "sample_limit": sample_limit,
        "pair_results": pair_results,
        "frequency_table": frequency_table,
        "most_common_output_difference": most_common_output_difference,
        "most_common_count": most_common_count,
    }


def build_sbox_difference_table(sbox):
    """
    Build a 16x4 difference distribution table for a 4x4 S-box.

    Rows correspond to input differences ΔX from 0..15 and columns correspond
    to output differences ΔY from 0..3. Each cell counts how many input pairs
    (x, x XOR ΔX) produce the given output difference.
    """
    if not isinstance(sbox, list) or len(sbox) != 4 or any(len(row) != 4 for row in sbox):
        raise ValueError("sbox must be a 4x4 table.")

    table = []
    for input_diff in range(16):
        row_counts = [0, 0, 0, 0]
        for x in range(16):
            x_prime = x ^ input_diff
            x_bits = format(x, "04b")
            x_prime_bits = format(x_prime, "04b")
            y = int(sbox_lookup(x_bits, sbox), 2)
            y_prime = int(sbox_lookup(x_prime_bits, sbox), 2)
            output_diff = y ^ y_prime
            row_counts[output_diff] += 1
        table.append({
            "input_difference": format(input_diff, "04b"),
            "output_diff_00": row_counts[0],
            "output_diff_01": row_counts[1],
            "output_diff_10": row_counts[2],
            "output_diff_11": row_counts[3],
        })

    return table

# ---------------------------------------------------------------------------
# Demo/report helpers
# ---------------------------------------------------------------------------

def run_test_case(name, key_10bit, plaintext_8bit):
    """
    Run one encrypt/decrypt round-trip test and print a clean report-friendly result.

    Returns:
        A dictionary containing the test name, key, plaintext, ciphertext,
        recovered plaintext, and round-trip status.
    """
    validate_10bit_key(key_10bit)
    validate_8bit_block(plaintext_8bit)

    ciphertext_8bit = encrypt_block(plaintext_8bit, key_10bit)
    recovered_plaintext = decrypt_block(ciphertext_8bit, key_10bit)
    roundtrip_ok = recovered_plaintext == plaintext_8bit

    result = {
        "name": name,
        "key": key_10bit,
        "plaintext": plaintext_8bit,
        "ciphertext": ciphertext_8bit,
        "recovered_plaintext": recovered_plaintext,
        "roundtrip_ok": roundtrip_ok,
    }

    print("=" * 48)
    print(f"TEST CASE: {name}")
    print("=" * 48)
    print(f"Key                 : {key_10bit}")
    print(f"Plaintext           : {plaintext_8bit}")
    print(f"Ciphertext          : {ciphertext_8bit}")
    print(f"Recovered Plaintext : {recovered_plaintext}")
    print(f"Round-trip OK       : {roundtrip_ok}")
    print("=" * 48)

    return result
