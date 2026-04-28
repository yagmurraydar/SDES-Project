"""
Validation script for the S-DES core implementation.

This file intentionally prints Expected / Actual / Result for the major
algorithm checks so the output can be used directly in a project report.
"""

from sdes_core import (
    S0,
    S1,
    apply_ip,
    apply_p10,
    decrypt_block,
    encrypt_block,
    fk,
    differential_pair_analysis,
    differential_experiment,
    build_sbox_difference_table,
    generate_subkeys,
    permute,
    sbox_lookup,
    validate_10bit_key,
    validate_8bit_block,
)


TEST_KEY = "1010000010"
TEST_PLAINTEXT = "11010111"
EXPECTED_K1 = "10100100"
EXPECTED_K2 = "01000011"
EXPECTED_CIPHERTEXT = "10101000"


def print_check(test_name, expected, actual):
    """Print one comparison in a report-friendly format."""
    result = "PASS" if expected == actual else "FAIL"
    print(f"[{test_name}]")
    print(f"Expected: {expected}")
    print(f"Actual:   {actual}")
    print(f"Result:   {result}")
    print()
    return result == "PASS"


def print_exception_check(test_name, func, expected_exception):
    """Print PASS when func raises the expected exception type."""
    print(f"[{test_name}]")
    print(f"Expected: {expected_exception.__name__}")
    try:
        func()
    except expected_exception as exc:
        print(f"Actual:   {type(exc).__name__}: {exc}")
        print("Result:   PASS")
        print()
        return True
    except Exception as exc:
        print(f"Actual:   {type(exc).__name__}: {exc}")
        print("Result:   FAIL")
        print()
        return False

    print("Actual:   no exception")
    print("Result:   FAIL")
    print()
    return False


def run_validation_tests():
    print("=== VALIDATION TESTS ===")
    results = []

    validate_10bit_key(TEST_KEY)
    results.append(print_check("valid 10-bit key acceptance", "accepted", "accepted"))

    results.append(
        print_exception_check(
            "invalid 10-bit key rejection",
            lambda: validate_10bit_key("10102"),
            ValueError,
        )
    )

    validate_8bit_block(TEST_PLAINTEXT)
    results.append(print_check("valid 8-bit block acceptance", "accepted", "accepted"))

    results.append(
        print_exception_check(
            "invalid 8-bit block rejection",
            lambda: validate_8bit_block("1010102"),
            ValueError,
        )
    )

    return all(results)


def run_helper_tests():
    print("=== HELPER TESTS ===")
    results = []

    results.append(
        print_check(
            "permute helper correctness",
            "1000001100",
            permute(TEST_KEY, [3, 5, 2, 7, 4, 10, 1, 9, 8, 6]),
        )
    )

    results.append(
        print_check(
            "apply_p10 correctness",
            "1000001100",
            apply_p10(TEST_KEY),
        )
    )

    results.append(
        print_check(
            "S-box lookup correctness",
            "01",
            sbox_lookup("1011", S0),
        )
    )

    return all(results)


def run_core_algorithm_tests():
    print("=== CORE ALGORITHM TESTS ===")
    results = []

    k1, k2, _ = generate_subkeys(TEST_KEY, verbose=True)
    results.append(print_check("subkey K1 generation", EXPECTED_K1, k1))
    results.append(print_check("subkey K2 generation", EXPECTED_K2, k2))

    fk_output, _ = fk("10101100", EXPECTED_K1, verbose=True)
    results.append(print_check("fk() sample correctness", "00101100", fk_output))

    results.append(
        print_check(
            "IP permutation correctness",
            "11011101",
            apply_ip(TEST_PLAINTEXT),
        )
    )

    ciphertext = encrypt_block(TEST_PLAINTEXT, TEST_KEY)
    results.append(
        print_check(
            "full encryption correctness",
            EXPECTED_CIPHERTEXT,
            ciphertext,
        )
    )

    decrypted_plaintext = decrypt_block(EXPECTED_CIPHERTEXT, TEST_KEY)
    results.append(
        print_check(
            "full decryption correctness",
            TEST_PLAINTEXT,
            decrypted_plaintext,
        )
    )

    roundtrip_plaintext = decrypt_block(encrypt_block(TEST_PLAINTEXT, TEST_KEY), TEST_KEY)
    results.append(
        print_check(
            "round-trip correctness",
            TEST_PLAINTEXT,
            roundtrip_plaintext,
        )
    )

    return all(results)



def run_differential_tests():
    print("=== DIFFERENTIAL CRYPTANALYSIS TESTS ===")
    results = []

    pair_result = differential_pair_analysis("11010111", "00000100", TEST_KEY)
    results.append(print_check("differential pair plaintext_2", "11010011", pair_result["plaintext_2"]))
    results.append(print_check("differential pair ciphertext_1", "10101000", pair_result["ciphertext_1"]))
    results.append(print_check("differential pair ciphertext_2", "11101001", pair_result["ciphertext_2"]))
    results.append(print_check("differential pair output difference", "01000001", pair_result["output_difference"]))

    experiment_result = differential_experiment("00000100", TEST_KEY, sample_limit=16)
    results.append(print_check("differential experiment sample size", 16, experiment_result["sample_limit"]))
    results.append(print_check("differential experiment pair count", 16, len(experiment_result["pair_results"])))
    results.append(print_check("differential experiment most common output difference", "01000101", experiment_result["most_common_output_difference"]))
    results.append(print_check("differential experiment most common count", 8, experiment_result["most_common_count"]))

    s0_ddt = build_sbox_difference_table(S0)
    s1_ddt = build_sbox_difference_table(S1)

    results.append(print_check("S0 DDT row count", 16, len(s0_ddt)))
    results.append(print_check("S1 DDT row count", 16, len(s1_ddt)))
    results.append(
        print_check(
            "S0 DDT zero-difference row",
            {
                "input_difference": "0000",
                "output_diff_00": 16,
                "output_diff_01": 0,
                "output_diff_10": 0,
                "output_diff_11": 0,
            },
            s0_ddt[0],
        )
    )
    results.append(
        print_check(
            "S1 DDT input difference 0001 row",
            {
                "input_difference": "0001",
                "output_diff_00": 2,
                "output_diff_01": 8,
                "output_diff_10": 2,
                "output_diff_11": 4,
            },
            s1_ddt[1],
        )
    )

    return all(results)

def show_decryption_trace_demo():
    print("=== VERBOSE DECRYPTION TRACE DEMO ===")
    plaintext, trace = decrypt_block(EXPECTED_CIPHERTEXT, TEST_KEY, verbose=True)

    print(f"Recovered plaintext: {plaintext}")
    print(f"subkeys: {trace['subkeys']}")
    print(f"after_ip: {trace['after_ip']}")
    print(f"round1_fk: {trace['round1_fk']}")
    print(f"after_sw: {trace['after_sw']}")
    print(f"round2_fk: {trace['round2_fk']}")
    print(f"after_ip_inverse: {trace['after_ip_inverse']}")
    print()


def main():
    all_passed = True
    all_passed &= run_validation_tests()
    all_passed &= run_helper_tests()
    all_passed &= run_core_algorithm_tests()
    all_passed &= run_differential_tests()
    show_decryption_trace_demo()

    print("=== SUMMARY ===")
    print(f"All tests passed: {all_passed}")


if __name__ == "__main__":
    main()
