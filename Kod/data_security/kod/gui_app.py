from __future__ import annotations

from typing import Any, Dict, List, Optional

import pandas as pd
import streamlit as st
from sdes_core import (
    EP_TABLE,
    IP_INV_TABLE,
    IP_TABLE,
    P10_TABLE,
    P4_TABLE,
    P8_TABLE,
    S0,
    S1,
    brute_force_attack_unique,
    build_sbox_difference_table,
    cbc_decrypt,
    cbc_encrypt,
    decrypt_block,
    differential_experiment,
    differential_pair_analysis,
    ecb_decrypt,
    ecb_encrypt,
    encrypt_block,
    format_output,
    generate_subkeys,
    ofb_decrypt,
    ofb_encrypt,
    parse_blocks_input,
    parse_input,
    validate_iv,
)

APP_TITLE = "S-DES Interactive Web Interface"
APP_DESCRIPTION = (
    "Interactive Streamlit interface for the S-DES project with guided single-block "
    "visualization, block cipher modes, visible reference tables, and brute-force analysis."
)


# -----------------------------------------------------------------------------
# Page / theme
# -----------------------------------------------------------------------------


def configure_page() -> None:
    st.set_page_config(
        page_title=APP_TITLE,
        page_icon="🔐",
        layout="wide",
        initial_sidebar_state="collapsed",
    )
    st.markdown(
        """
        <style>
            :root {
                --bg:#050d1a; --bg2:#091526; --card:#0d1f35; --card2:#0a1928;
                --cyan:#00e5ff; --teal:#00b4d8; --blue:#4895ef; --green:#00f5a0;
                --red:#ff4d6d; --amber:#ffb703; --purple:#c77dff; --dim:#7d95ad;
                --light:#b8cbdd; --border:#1a3352; --white:#ffffff;
            }
            .stApp {
                background: linear-gradient(180deg, var(--bg) 0%, #081322 100%);
            }
            .block-container {
                padding-top: 3rem;
                padding-bottom: 2rem;
                max-width: 1450px;
            }
            .main-title {
                font-size: 2.1rem;
                font-weight: 800;
                color: var(--white);
                margin-bottom: 0.2rem;
            }
            .main-desc {
                color: var(--light);
                line-height: 1.7;
                margin-bottom: 1rem;
            }
            .hero {
                background: linear-gradient(180deg, rgba(9,21,38,.98) 0%, rgba(6,16,29,.98) 100%);
                border: 1px solid var(--border);
                border-radius: 18px;
                padding: 1.2rem 1.3rem;
                margin-bottom: 1rem;
                box-shadow: 0 0 0 1px rgba(0,229,255,.03), 0 20px 40px rgba(0,0,0,.18);
            }
            .kicker {
                color: var(--cyan);
                letter-spacing: .18em;
                text-transform: uppercase;
                font-size: .73rem;
                font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
                margin-bottom: .4rem;
            }
            .hero-title {
                color: var(--white);
                font-size: 1.95rem;
                line-height: 1.05;
                font-weight: 800;
                margin: 0 0 .35rem 0;
            }
            .hero-desc {
                color: var(--light);
                line-height: 1.7;
                max-width: 900px;
                font-size: .98rem;
            }
            .panel {
                background: rgba(13,31,53,.97);
                border: 1px solid var(--border);
                border-radius: 16px;
                padding: 1rem 1rem;
                margin-bottom: 1rem;
            }
            .panel-title {
                color: var(--cyan);
                font-size: .78rem;
                letter-spacing: .15em;
                text-transform: uppercase;
                font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
                margin-bottom: .7rem;
            }
            .metric-card {
                background: rgba(10,25,40,.96);
                border: 1px solid var(--border);
                border-radius: 14px;
                padding: .95rem 1rem;
                min-height: 112px;
            }
            .metric-label {
                color: var(--dim);
                font-size: .73rem;
                text-transform: uppercase;
                letter-spacing: .12em;
                font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
                margin-bottom: .45rem;
            }
            .metric-value {
                color: var(--white);
                font-weight: 800;
                font-size: 1.32rem;
                line-height: 1.15;
                word-break: break-word;
            }
            .metric-note {
                color: var(--light);
                margin-top: .5rem;
                line-height: 1.55;
                font-size: .9rem;
            }
            .step-box {
                background: rgba(10,25,40,.96);
                border: 1px solid var(--border);
                border-radius: 14px;
                padding: 1rem 1rem;
                min-height: 420px;
            }
            .step-phase {
                color: var(--cyan);
                text-transform: uppercase;
                letter-spacing: .16em;
                font-size: .74rem;
                font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
                margin-bottom: .35rem;
            }
            .step-title {
                color: var(--white);
                font-size: 1.55rem;
                font-weight: 800;
                line-height: 1.1;
                margin-bottom: .45rem;
            }
            .step-desc {
                color: var(--light);
                line-height: 1.7;
                margin-bottom: .9rem;
            }
            .bitline {
                font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
                color: var(--green);
                font-size: 1.1rem;
                letter-spacing: .14em;
                word-break: break-all;
                margin-bottom: .6rem;
            }
            .kv {
                background: rgba(5,13,26,.45);
                border: 1px solid rgba(26,51,82,.85);
                border-radius: 12px;
                padding: .8rem .9rem;
                margin-bottom: .75rem;
            }
            .kv-key {
                color: var(--dim);
                font-size: .72rem;
                text-transform: uppercase;
                letter-spacing: .12em;
                font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
                margin-bottom: .3rem;
            }
            .kv-value {
                color: var(--white);
                font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
                word-break: break-word;
            }
            .flow-item {
                border: 1px solid var(--border);
                background: rgba(10,25,40,.92);
                border-radius: 10px;
                padding: .6rem .75rem;
                color: var(--light);
                margin-bottom: .45rem;
                font-size: .92rem;
            }
            .flow-item.active {
                border-color: var(--cyan);
                box-shadow: 0 0 0 1px rgba(0,229,255,.18);
                color: var(--white);
                background: rgba(0,229,255,.07);
            }
            .flow-item.done {
                border-color: rgba(0,245,160,.26);
                color: #c8ffe9;
            }
            .mini-note {
                color: var(--dim);
                font-size: .86rem;
                line-height: 1.6;
            }
            div[data-testid="stDataFrame"] {
                background: rgba(10,25,40,.65);
                border: 1px solid var(--border);
                border-radius: 12px;
                padding: .25rem;
            }
            textarea, input, .stSelectbox div[data-baseweb="select"], .stTextArea textarea {
                background-color: #081322 !important;
                color: white !important;
            }
            div.stButton > button, div.stDownloadButton > button {
                border-radius: 12px;
                border: 1px solid var(--border);
                background: linear-gradient(180deg, #0d1f35 0%, #0a1928 100%);
                color: white;
            }
            div.stButton > button:hover, div.stDownloadButton > button:hover {
                border-color: var(--cyan);
                color: var(--cyan);
            }
            .stTabs [data-baseweb="tab-list"] {
                gap: .4rem;
            }
            .stTabs [data-baseweb="tab"] {
                background: rgba(13,31,53,.8);
                border: 1px solid var(--border);
                border-radius: 10px 10px 0 0;
                color: white;
            }
            .stAlert {
                border-radius: 12px;
            }
            .codebox pre {
                white-space: pre-wrap;
            }
        </style>
        """,
        unsafe_allow_html=True,
    )


# -----------------------------------------------------------------------------
# Shared helpers
# -----------------------------------------------------------------------------


def parse_key_value(raw_key: str, key_format: str) -> str:
    raw_key = raw_key.strip()
    normalized = key_format.strip().lower()
    if normalized == "binary":
        if len(raw_key) != 10 or set(raw_key) - {"0", "1"}:
            raise ValueError("Key must be a 10-bit binary string.")
        return raw_key
    if normalized == "decimal":
        try:
            key_value = int(raw_key)
        except ValueError as exc:
            raise ValueError("Decimal key must be an integer from 0 to 1023.") from exc
        if not 0 <= key_value <= 1023:
            raise ValueError("Decimal key must be in range 0 to 1023.")
        return format(key_value, "010b")
    raise ValueError("Key format must be Binary or Decimal.")


def block_views_df(binary_block: str) -> pd.DataFrame:
    views = format_output(binary_block)
    return pd.DataFrame(
        {
            "Representation": ["Binary", "Decimal", "ASCII"],
            "Value": [views["binary"], views["decimal"], views["ascii"]],
        }
    )


def permutation_tables_df() -> pd.DataFrame:
    max_len = max(
        len(P10_TABLE), len(P8_TABLE), len(P4_TABLE), len(IP_TABLE), len(IP_INV_TABLE), len(EP_TABLE)
    )

    def pad(values: List[int]) -> List[Optional[int]]:
        return values + [None] * (max_len - len(values))

    return pd.DataFrame(
        {
            "P10": pad(P10_TABLE),
            "P8": pad(P8_TABLE),
            "P4": pad(P4_TABLE),
            "IP": pad(IP_TABLE),
            "IP^-1": pad(IP_INV_TABLE),
            "EP": pad(EP_TABLE),
        }
    )


def sbox_df(sbox: List[List[int]]) -> pd.DataFrame:
    return pd.DataFrame(sbox, columns=["00", "01", "10", "11"], index=["00", "01", "10", "11"])


def show_download_button(filename: str, text: str, label: str) -> None:
    st.download_button(label=label, data=text, file_name=filename, mime="text/plain", use_container_width=True)


def hero(kicker: str, title: str, desc: str) -> None:
    st.markdown(
        f"""
        <div class="hero">
            <div class="kicker">{kicker}</div>
            <div class="hero-title">{title}</div>
            <div class="hero-desc">{desc}</div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def metric_card(label: str, value: str, note: str = "") -> None:
    st.markdown(
        f"""
        <div class="metric-card">
            <div class="metric-label">{label}</div>
            <div class="metric-value">{value}</div>
            {f'<div class="metric-note">{note}</div>' if note else ''}
        </div>
        """,
        unsafe_allow_html=True,
    )


def kv_block(key: str, value: str) -> None:
    st.markdown(
        f"""
        <div class="kv">
            <div class="kv-key">{key}</div>
            <div class="kv-value">{value}</div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def flow_panel(step_titles: List[str], current_step: int, title: str = "Interactive Flow") -> None:
    items = []
    for idx, step_title in enumerate(step_titles):
        cls = "flow-item"
        if idx < current_step:
            cls += " done"
        if idx == current_step:
            cls += " active"
        items.append(f'<div class="{cls}">{idx+1:02d}. {step_title}</div>')
    st.markdown(
        f"<div class='panel'><div class='panel-title'>{title}</div>{''.join(items)}</div>",
        unsafe_allow_html=True,
    )


# -----------------------------------------------------------------------------
# Single-block step builder
# -----------------------------------------------------------------------------


def build_key_schedule_trace(key_binary: str) -> Dict[str, Any]:
    k1, k2, trace = generate_subkeys(key_binary, verbose=True)
    return {"K1": k1, "K2": k2, **trace}


SINGLE_STEP_TITLES = [
    "Input",
    "P10",
    "LS-1",
    "P8 → K1",
    "LS-2",
    "P8 → K2",
    "Initial Permutation",
    "Round 1",
    "Switch",
    "Round 2",
    "Final Output",
]


SINGLE_STEP_PHASES = [
    "Input",
    "Key Scheduling",
    "Key Scheduling",
    "Key Scheduling",
    "Key Scheduling",
    "Key Scheduling",
    "Encryption / Decryption",
    "Round 1",
    "Switch",
    "Round 2",
    "Result",
]


SINGLE_STEP_DESCRIPTIONS = [
    "The session begins with one 10-bit key and one 8-bit block. The block is plaintext for encryption and ciphertext for decryption.",
    "P10 permutes the 10-bit key to prepare the key schedule. This is the first mandatory step in the project report.",
    "The P10 output is split into two 5-bit halves, then both halves are circularly shifted left by 1 bit.",
    "P8 selects 8 of the 10 shifted bits and produces K1, the first round subkey.",
    "Starting from the LS-1 state, both 5-bit halves are rotated left by 2 more positions.",
    "Applying P8 again produces K2, the second round subkey used in the second Feistel round.",
    "The input block is permuted with IP before entering the Feistel structure.",
    "Round 1 applies expansion/permutation, XOR with the round subkey, S-box substitutions, P4, and left-half XOR.",
    "After the first round, the left and right 4-bit halves are swapped with SW.",
    "Round 2 repeats the same Feistel logic with the other subkey.",
    "The final 8-bit block is obtained by IP inverse. This is the final ciphertext or recovered plaintext.",
]


def build_single_steps(
    operation: str,
    key_binary: str,
    input_value: str,
    input_binary: str,
    output_block: str,
    trace: Dict[str, Any],
) -> List[Dict[str, Any]]:
    key_trace = build_key_schedule_trace(key_binary)
    round1_subkey = key_trace["K1"] if operation == "Encrypt" else key_trace["K2"]
    round2_subkey = key_trace["K2"] if operation == "Encrypt" else key_trace["K1"]

    return [
        {
            "phase": SINGLE_STEP_PHASES[0],
            "title": SINGLE_STEP_TITLES[0],
            "desc": SINGLE_STEP_DESCRIPTIONS[0],
            "items": {
                "Operation": operation,
                "Key (Binary)": key_binary,
                "Input Value": input_value,
                "Internal Binary": input_binary,
            },
            "highlight": input_binary,
        },
        {
            "phase": SINGLE_STEP_PHASES[1],
            "title": SINGLE_STEP_TITLES[1],
            "desc": SINGLE_STEP_DESCRIPTIONS[1],
            "items": {
                "Original Key": key_trace["original_key"],
                "P10 Table": str(P10_TABLE),
                "After P10": key_trace["after_p10"],
            },
            "highlight": key_trace["after_p10"],
        },
        {
            "phase": SINGLE_STEP_PHASES[2],
            "title": SINGLE_STEP_TITLES[2],
            "desc": SINGLE_STEP_DESCRIPTIONS[2],
            "items": {
                "Left Half": key_trace["left_p10"],
                "Right Half": key_trace["right_p10"],
                "After LS-1 Left": key_trace["after_ls1_left"],
                "After LS-1 Right": key_trace["after_ls1_right"],
            },
            "highlight": f"{key_trace['after_ls1_left']} | {key_trace['after_ls1_right']}",
        },
        {
            "phase": SINGLE_STEP_PHASES[3],
            "title": SINGLE_STEP_TITLES[3],
            "desc": SINGLE_STEP_DESCRIPTIONS[3],
            "items": {
                "P8 Table": str(P8_TABLE),
                "K1": key_trace["K1"],
            },
            "highlight": key_trace["K1"],
        },
        {
            "phase": SINGLE_STEP_PHASES[4],
            "title": SINGLE_STEP_TITLES[4],
            "desc": SINGLE_STEP_DESCRIPTIONS[4],
            "items": {
                "After LS-2 Left": key_trace["after_ls2_left"],
                "After LS-2 Right": key_trace["after_ls2_right"],
            },
            "highlight": f"{key_trace['after_ls2_left']} | {key_trace['after_ls2_right']}",
        },
        {
            "phase": SINGLE_STEP_PHASES[5],
            "title": SINGLE_STEP_TITLES[5],
            "desc": SINGLE_STEP_DESCRIPTIONS[5],
            "items": {
                "P8 Table": str(P8_TABLE),
                "K2": key_trace["K2"],
            },
            "highlight": key_trace["K2"],
        },
        {
            "phase": SINGLE_STEP_PHASES[6],
            "title": SINGLE_STEP_TITLES[6],
            "desc": SINGLE_STEP_DESCRIPTIONS[6],
            "items": {
                "Input Binary": input_binary,
                "IP Table": str(IP_TABLE),
                "After IP": trace["after_ip"],
            },
            "highlight": trace["after_ip"],
        },
        {
            "phase": SINGLE_STEP_PHASES[7],
            "title": SINGLE_STEP_TITLES[7],
            "desc": SINGLE_STEP_DESCRIPTIONS[7],
            "items": {
                "Round Subkey": round1_subkey,
                "L": trace["round1_fk"]["L"],
                "R": trace["round1_fk"]["R"],
                "EP(R)": trace["round1_fk"]["EP_R"],
                "XOR with Subkey": trace["round1_fk"]["xor_with_subkey"],
                "S0 Output": trace["round1_fk"]["S0_output"],
                "S1 Output": trace["round1_fk"]["S1_output"],
                "P4 Output": trace["round1_fk"]["P4_output"],
                "Final Block": trace["round1_fk"]["final_block"],
            },
            "highlight": trace["round1_fk"]["final_block"],
        },
        {
            "phase": SINGLE_STEP_PHASES[8],
            "title": SINGLE_STEP_TITLES[8],
            "desc": SINGLE_STEP_DESCRIPTIONS[8],
            "items": {
                "After Round 1": trace["round1_fk"]["final_block"],
                "After SW": trace["after_sw"],
            },
            "highlight": trace["after_sw"],
        },
        {
            "phase": SINGLE_STEP_PHASES[9],
            "title": SINGLE_STEP_TITLES[9],
            "desc": SINGLE_STEP_DESCRIPTIONS[9],
            "items": {
                "Round Subkey": round2_subkey,
                "L": trace["round2_fk"]["L"],
                "R": trace["round2_fk"]["R"],
                "EP(R)": trace["round2_fk"]["EP_R"],
                "XOR with Subkey": trace["round2_fk"]["xor_with_subkey"],
                "S0 Output": trace["round2_fk"]["S0_output"],
                "S1 Output": trace["round2_fk"]["S1_output"],
                "P4 Output": trace["round2_fk"]["P4_output"],
                "Final Block": trace["round2_fk"]["final_block"],
            },
            "highlight": trace["round2_fk"]["final_block"],
        },
        {
            "phase": SINGLE_STEP_PHASES[10],
            "title": SINGLE_STEP_TITLES[10],
            "desc": SINGLE_STEP_DESCRIPTIONS[10],
            "items": {
                "IP^-1 Table": str(IP_INV_TABLE),
                "Output Binary": output_block,
                "Output Decimal": str(format_output(output_block)["decimal"]),
                "Output ASCII": str(format_output(output_block)["ascii"]),
            },
            "highlight": output_block,
        },
    ]


def build_single_result_text(
    operation: str,
    key_binary: str,
    input_format: str,
    input_value: str,
    input_binary: str,
    output_binary: str,
    trace: Dict[str, Any],
) -> str:
    key_trace = build_key_schedule_trace(key_binary)
    output_views = format_output(output_binary)
    lines = [
        "S-DES SINGLE BLOCK RESULT",
        "=" * 40,
        f"Operation          : {operation}",
        f"Key (Binary)       : {key_binary}",
        f"Input Format       : {input_format}",
        f"Input Value        : {input_value}",
        f"Internal Binary    : {input_binary}",
        f"Output Binary      : {output_views['binary']}",
        f"Output Decimal     : {output_views['decimal']}",
        f"Output ASCII       : {output_views['ascii']}",
        "",
        "KEY SCHEDULING",
        "-" * 40,
        f"After P10          : {key_trace['after_p10']}",
        f"After LS-1 Left    : {key_trace['after_ls1_left']}",
        f"After LS-1 Right   : {key_trace['after_ls1_right']}",
        f"K1                 : {key_trace['K1']}",
        f"After LS-2 Left    : {key_trace['after_ls2_left']}",
        f"After LS-2 Right   : {key_trace['after_ls2_right']}",
        f"K2                 : {key_trace['K2']}",
        "",
        "ROUND 1",
        "-" * 40,
    ]
    for k, v in trace["round1_fk"].items():
        lines.append(f"{k:<20}: {v}")
    lines.extend(["", "ROUND 2", "-" * 40])
    for k, v in trace["round2_fk"].items():
        lines.append(f"{k:<20}: {v}")
    lines.extend(["", f"After IP Inverse   : {trace['after_ip_inverse']}"])
    return "\n".join(lines)


# -----------------------------------------------------------------------------
# Attack helpers
# -----------------------------------------------------------------------------


def find_unique_bruteforce_key(plaintext_binary: str, ciphertext_binary: str) -> Dict[str, Any]:
    result = brute_force_attack_unique(plaintext_binary, ciphertext_binary, verbose=True)
    matching_keys = result["matching_keys"]
    unique_key = matching_keys[0] if len(matching_keys) == 1 else None
    result["unique_key"] = unique_key
    result["is_unique_match"] = unique_key is not None
    result["ambiguity_reason"] = None if unique_key is not None else (
        "No unique key can be proven from the provided plaintext/ciphertext pair."
    )
    return result


ATTACK_EXAMPLES = {
    "Reference Example": {
        "plaintext_format": "Binary",
        "plaintext": "11010111",
        "ciphertext_format": "Binary",
        "ciphertext": "10101000",
        "note": "Classic example where 1010000010 is a matching candidate key.",
    },
    "T-01 Style": {
        "plaintext_format": "Binary",
        "plaintext": "10101010",
        "ciphertext_format": "Binary",
        "ciphertext": "00010001",
        "note": "Validation-style example aligned with the report test table format.",
    },
}


def build_bruteforce_attempts(plaintext_binary: str, ciphertext_binary: str) -> pd.DataFrame:
    rows = []
    for key_value in range(1024):
        candidate_key = format(key_value, "010b")
        produced_ciphertext = encrypt_block(plaintext_binary, candidate_key)
        rows.append(
            {
                "Step": key_value + 1,
                "Candidate Key": candidate_key,
                "Produced Ciphertext": produced_ciphertext,
                "Expected Ciphertext": ciphertext_binary,
                "Match": produced_ciphertext == ciphertext_binary,
            }
        )
    return pd.DataFrame(rows)


def build_attack_result_text(
    plaintext_format: str,
    plaintext_raw: str,
    plaintext_binary: str,
    ciphertext_format: str,
    ciphertext_raw: str,
    ciphertext_binary: str,
    result: Dict[str, Any],
) -> str:
    unique_key = result.get("unique_key")
    matching_keys = result.get("matching_keys", [])

    lines = [
        "S-DES BRUTE-FORCE ATTACK RESULT",
        "=" * 40,
        f"Plaintext Format   : {plaintext_format}",
        f"Plaintext Input    : {plaintext_raw}",
        f"Plaintext Binary   : {plaintext_binary}",
        f"Ciphertext Format  : {ciphertext_format}",
        f"Ciphertext Input   : {ciphertext_raw}",
        f"Ciphertext Binary  : {ciphertext_binary}",
        "",
        "ATTACK SUMMARY",
        "-" * 40,
        f"Total Tested Keys  : {result['total_tested_keys']}",
        f"Elapsed Time (s)   : {result['elapsed_time']:.6f}",
        f"Matching Key Count : {len(matching_keys)}",
        f"Unique Match Found : {result.get('is_unique_match', False)}",
        "",
        "FINAL RESULT",
        "-" * 40,
    ]

    if unique_key is not None:
        lines.append(f"Unique Matching Key: {unique_key}")
    else:
        lines.append(result.get("ambiguity_reason", "No unique key found."))

    lines.extend([
        "",
        "MATCHING CANDIDATE KEYS",
        "-" * 40,
    ])

    if matching_keys:
        lines.extend(matching_keys)
    else:
        lines.append("No matching key found.")

    return "\n".join(lines)


# -----------------------------------------------------------------------------
# Modes helpers
# -----------------------------------------------------------------------------


def sanitize_block_trace(mode: str, block_trace: Dict[str, Any]) -> List[Dict[str, str]]:
    ordered_rows: List[Dict[str, str]] = []

    def add(label: str, value: Any) -> None:
        if value is None:
            return
        if isinstance(value, (dict, list, tuple)):
            return
        ordered_rows.append({"Field": label, "Value": str(value)})

    add("Block Index", block_trace.get("block_index"))

    if mode == "ECB":
        add("Input Block", block_trace.get("input_block"))
        add("Output Block", block_trace.get("output_block"))
    elif mode == "CBC":
        add("Input Block", block_trace.get("input_block"))
        add("Chaining Value", block_trace.get("chaining_value"))
        add("XOR Result", block_trace.get("xor_result"))
        add("Decrypted Before XOR", block_trace.get("decrypted_before_xor"))
        add("Recovered Block", block_trace.get("recovered_block"))
        add("Output Block", block_trace.get("output_block"))
    elif mode == "OFB":
        add("Input Block", block_trace.get("input_block"))
        add("Feedback Value", block_trace.get("feedback_value"))
        add("Keystream Block", block_trace.get("keystream_block"))
        add("Output Block", block_trace.get("output_block"))

    return ordered_rows


def build_mode_result_text(
    mode: str,
    operation: str,
    key_binary: str,
    input_blocks: List[str],
    output_blocks: List[str],
    trace: Dict[str, Any],
    iv_binary: Optional[str],
) -> str:
    lines = [
        "S-DES MULTI-BLOCK MODE RESULT",
        "=" * 40,
        f"Mode               : {mode}",
        f"Operation          : {operation}",
        f"Key (Binary)       : {key_binary}",
    ]
    if iv_binary is not None:
        lines.append(f"IV                 : {iv_binary}")

    lines.extend([
        f"Input Blocks       : {' '.join(input_blocks)}",
        f"Output Blocks      : {' '.join(output_blocks)}",
        "",
        "TRACE PREVIEW",
        "-" * 40,
    ])

    for block_trace in trace["steps"]["blocks"]:
        lines.append(f"Block {block_trace['block_index']}")
        clean_rows = sanitize_block_trace(mode, block_trace)
        for row in clean_rows:
            lines.append(f"  {row['Field']:<20}: {row['Value']}")
        lines.append("")

    return "\n".join(lines)


# -----------------------------------------------------------------------------
# Differential helpers
# -----------------------------------------------------------------------------


def differential_frequency_df(frequency_table: List[Dict[str, Any]]) -> pd.DataFrame:
    return pd.DataFrame(
        {
            "Output Difference": [row["output_difference"] for row in frequency_table],
            "Count": [row["count"] for row in frequency_table],
        }
    )


def differential_pairs_df(pair_results: List[Dict[str, Any]]) -> pd.DataFrame:
    return pd.DataFrame(
        {
            "Pair Index": [row["pair_index"] for row in pair_results],
            "P1": [row["plaintext_1"] for row in pair_results],
            "P2": [row["plaintext_2"] for row in pair_results],
            "ΔP": [row["input_difference"] for row in pair_results],
            "C1": [row["ciphertext_1"] for row in pair_results],
            "C2": [row["ciphertext_2"] for row in pair_results],
            "ΔC": [row["output_difference"] for row in pair_results],
        }
    )


def sbox_difference_df(rows: List[Dict[str, Any]]) -> pd.DataFrame:
    return pd.DataFrame(
        {
            "ΔX": [row["input_difference"] for row in rows],
            "ΔY=00": [row["output_diff_00"] for row in rows],
            "ΔY=01": [row["output_diff_01"] for row in rows],
            "ΔY=10": [row["output_diff_10"] for row in rows],
            "ΔY=11": [row["output_diff_11"] for row in rows],
        }
    )


def build_differential_result_text(
    key_binary: str,
    plaintext_binary: str,
    input_difference: str,
    pair_result: Dict[str, Any],
    experiment_result: Dict[str, Any],
) -> str:
    lines = [
        "S-DES DIFFERENTIAL CRYPTANALYSIS RESULT",
        "=" * 44,
        f"Key (Binary)             : {key_binary}",
        f"Reference Plaintext      : {plaintext_binary}",
        f"Input Difference (ΔP)    : {input_difference}",
        "",
        "SINGLE-PAIR ANALYSIS",
        "-" * 44,
        f"P1                       : {pair_result['plaintext_1']}",
        f"P2                       : {pair_result['plaintext_2']}",
        f"C1                       : {pair_result['ciphertext_1']}",
        f"C2                       : {pair_result['ciphertext_2']}",
        f"Output Difference (ΔC)   : {pair_result['output_difference']}",
        "",
        "FREQUENCY EXPERIMENT",
        "-" * 44,
        f"Sample Limit             : {experiment_result['sample_limit']}",
        f"Most Common ΔC           : {experiment_result['most_common_output_difference']}",
        f"Most Common Count        : {experiment_result['most_common_count']}",
        "",
        "TOP OUTPUT DIFFERENCES",
        "-" * 44,
    ]
    for row in experiment_result["frequency_table"][:10]:
        lines.append(f"{row['output_difference']} : {row['count']}")
    return "\n".join(lines)


# -----------------------------------------------------------------------------
# Reference
# -----------------------------------------------------------------------------


def render_reference_section() -> None:
    with st.expander("Reference Tables: P10, P8, P4, IP, IP^-1, EP, S0, S1", expanded=False):
        left, right = st.columns([1.1, 1])
        with left:
            st.markdown("#### Permutation Tables")
            st.dataframe(permutation_tables_df(), use_container_width=True, hide_index=True)
        with right:
            st.markdown("#### S-Boxes")
            s0_col, s1_col = st.columns(2)
            with s0_col:
                st.dataframe(sbox_df(S0), use_container_width=True)
            with s1_col:
                st.dataframe(sbox_df(S1), use_container_width=True)


# -----------------------------------------------------------------------------
# Tabs
# -----------------------------------------------------------------------------


def render_single_block_tab() -> None:
    hero(
        "Single Block",
        "Encrypt / Decrypt — Interactive Trace",
        "Run one S-DES block and inspect the result step by step. The current phase is shown in a clean main column, while the right column keeps the final result summary visible.",
    )

    with st.form("single_block_form"):
        c1, c2, c3 = st.columns(3)
        with c1:
            operation = st.radio("Operation", ["Encrypt", "Decrypt"], horizontal=True)
        with c2:
            key_format = st.selectbox("Key Format", ["Binary", "Decimal"])
        with c3:
            block_format = st.selectbox("Block Format", ["Binary", "Decimal", "ASCII"])

        key_value = st.text_input("Key", placeholder="Example: 1010000010 or 642")
        block_value = st.text_input("Input Block", placeholder="Example: 11010111 or 215 or A")
        submitted = st.form_submit_button("Run Interactive Session", use_container_width=True)

    if submitted:
        try:
            key_binary = parse_key_value(key_value, key_format)
            input_binary = parse_input(block_value, block_format.lower())
            if operation == "Encrypt":
                output_block, trace = encrypt_block(input_binary, key_binary, verbose=True)
            else:
                output_block, trace = decrypt_block(input_binary, key_binary, verbose=True)

            st.session_state.single_result = {
                "operation": operation,
                "key_binary": key_binary,
                "input_format": block_format,
                "input_value": block_value,
                "input_binary": input_binary,
                "output_block": output_block,
                "trace": trace,
                "steps": build_single_steps(operation, key_binary, block_value, input_binary, output_block, trace),
                "result_text": build_single_result_text(operation, key_binary, block_format, block_value, input_binary, output_block, trace),
            }
            st.session_state.single_step_index = 0
            st.success(f"{operation} completed successfully.")
        except (TypeError, ValueError) as exc:
            st.error(f"Input error: {exc}")

    if "single_result" not in st.session_state:
        st.info("Run a session first to open the interactive trace view.")
        return

    data = st.session_state.single_result
    steps = data["steps"]
    if "single_step_index" not in st.session_state:
        st.session_state.single_step_index = 0
    step_index = max(0, min(st.session_state.single_step_index, len(steps) - 1))
    st.session_state.single_step_index = step_index
    current_step = steps[step_index]

    main_col, result_col = st.columns([1.45, 1.0], gap="large")
    with main_col:
        flow_panel(SINGLE_STEP_TITLES, step_index)
        col_a, col_b, col_c = st.columns([1, 1, 1.2])
        with col_a:
            if st.button("← Previous Step", use_container_width=True, disabled=step_index == 0):
                st.session_state.single_step_index -= 1
                st.rerun()
        with col_b:
            if st.button("Next Step →", use_container_width=True, disabled=step_index == len(steps) - 1):
                st.session_state.single_step_index += 1
                st.rerun()
        with col_c:
            st.slider("Step", 1, len(steps), step_index + 1, key="single_slider")
            if st.session_state.single_slider != step_index + 1:
                st.session_state.single_step_index = st.session_state.single_slider - 1
                st.rerun()

        st.markdown(
            f"""
            <div class="step-box">
                <div class="step-phase">{current_step['phase']}</div>
                <div class="step-title">{current_step['title']}</div>
                <div class="step-desc">{current_step['desc']}</div>
                <div class="bitline">{current_step['highlight']}</div>
            </div>
            """,
            unsafe_allow_html=True,
        )
        for key, value in current_step["items"].items():
            kv_block(key, str(value))

    with result_col:
        st.markdown("#### Full Result")
        st.text_area("Single-block summary", value=data["result_text"], height=620)
        st.markdown("#### Output Views")
        st.dataframe(block_views_df(data["output_block"]), use_container_width=True, hide_index=True)
        show_download_button("sdes_single_block_result.txt", data["result_text"], "Download Single-Block Result")


def render_modes_tab() -> None:
    hero(
        "Block Modes",
        "ECB / CBC / OFB — Multi-Block View",
        "Run multi-block operations and inspect the output block by block. This section is optimized for screenshots that show chaining behavior and the difference between modes.",
    )

    with st.form("modes_form"):
        c1, c2, c3 = st.columns(3)
        with c1:
            mode = st.selectbox("Mode", ["ECB", "CBC", "OFB"])
        with c2:
            operation = st.radio("Operation", ["Encrypt", "Decrypt"], horizontal=True)
        with c3:
            key_format = st.selectbox("Key Format", ["Binary", "Decimal"])

        key_value = st.text_input("Key", placeholder="Example: 1010000010")
        blocks_value = st.text_area("Blocks", placeholder="11010111 01000001 10101010", height=110)
        iv_value = st.text_input("IV", placeholder="Required for CBC/OFB", disabled=(mode == "ECB"))
        submitted = st.form_submit_button("Run Mode Session", use_container_width=True)

    if submitted:
        try:
            key_binary = parse_key_value(key_value, key_format)
            input_blocks = parse_blocks_input(blocks_value)
            iv_binary: Optional[str] = None
            if mode != "ECB":
                iv_binary = iv_value.strip()
                validate_iv(iv_binary)

            if mode == "ECB" and operation == "Encrypt":
                output_blocks, trace = ecb_encrypt(input_blocks, key_binary, verbose=True)
            elif mode == "ECB" and operation == "Decrypt":
                output_blocks, trace = ecb_decrypt(input_blocks, key_binary, verbose=True)
            elif mode == "CBC" and operation == "Encrypt":
                output_blocks, trace = cbc_encrypt(input_blocks, key_binary, iv_binary, verbose=True)
            elif mode == "CBC" and operation == "Decrypt":
                output_blocks, trace = cbc_decrypt(input_blocks, key_binary, iv_binary, verbose=True)
            elif mode == "OFB" and operation == "Encrypt":
                output_blocks, trace = ofb_encrypt(input_blocks, key_binary, iv_binary, verbose=True)
            else:
                output_blocks, trace = ofb_decrypt(input_blocks, key_binary, iv_binary, verbose=True)

            st.session_state.mode_result = {
                "mode": mode,
                "operation": operation,
                "key_binary": key_binary,
                "input_blocks": input_blocks,
                "output_blocks": output_blocks,
                "trace": trace,
                "iv_binary": iv_binary,
                "result_text": build_mode_result_text(mode, operation, key_binary, input_blocks, output_blocks, trace, iv_binary),
            }
            st.success(f"{mode} {operation.lower()} completed successfully.")
        except (TypeError, ValueError) as exc:
            st.error(f"Input error: {exc}")

    if "mode_result" not in st.session_state:
        st.info("Run a mode session first to inspect block outputs.")
        return

    data = st.session_state.mode_result
    m1, m2, m3 = st.columns(3)
    with m1:
        metric_card("Mode", data["mode"], "Selected block cipher mode.")
    with m2:
        metric_card("Operation", data["operation"], "Encrypt or decrypt mode session.")
    with m3:
        metric_card("Block Count", str(len(data["input_blocks"])), "Total number of processed 8-bit blocks.")

    st.markdown("#### Input / Output Summary")
    summary_df = pd.DataFrame(
        {
            "Index": list(range(len(data["input_blocks"]))),
            "Input Block": data["input_blocks"],
            "Output Block": data["output_blocks"],
        }
    )
    st.dataframe(summary_df, use_container_width=True, hide_index=True)

    st.markdown("#### Per-Block Interactive Trace")
    block_index = st.selectbox("Choose block index", list(range(len(data["trace"]["steps"]["blocks"]))))
    block_trace = data["trace"]["steps"]["blocks"][block_index]
    trace_rows = sanitize_block_trace(data["mode"], block_trace)
    st.dataframe(pd.DataFrame(trace_rows), use_container_width=True, hide_index=True)

    st.markdown("#### Full Mode Result")
    st.text_area("Copyable mode result", value=data["result_text"], height=340)
    show_download_button(
        f"sdes_{data['mode'].lower()}_{data['operation'].lower()}_result.txt",
        data["result_text"],
        "Download Mode Result",
    )


def render_attack_tab() -> None:
    hero(
        "Attack Module",
        "Brute-Force Attack — Interactive Candidate Search",
        "This screen turns the attack into an explainable process. You can load an example, run the search, inspect candidate-key attempts, and move through the early attack steps or jump directly to matching keys.",
    )

    c_load, c_note = st.columns([1, 2])
    with c_load:
        selected_example = st.selectbox("Quick Example", ["None"] + list(ATTACK_EXAMPLES.keys()))
        if st.button("Load Example", use_container_width=True):
            if selected_example != "None":
                ex = ATTACK_EXAMPLES[selected_example]
                st.session_state.attack_plaintext_format = ex["plaintext_format"]
                st.session_state.attack_plaintext = ex["plaintext"]
                st.session_state.attack_ciphertext_format = ex["ciphertext_format"]
                st.session_state.attack_ciphertext = ex["ciphertext"]
                st.rerun()
    with c_note:
        if selected_example != "None":
            st.info(ATTACK_EXAMPLES[selected_example]["note"])
        else:
            st.caption("Load one of the prepared examples for a faster demo setup.")

    with st.form("attack_form"):
        c1, c2 = st.columns(2)
        with c1:
            plaintext_format = st.selectbox(
                "Plaintext Format",
                ["Binary", "Decimal", "ASCII"],
                key="attack_plaintext_format",
            )
            plaintext_value = st.text_input(
                "Known Plaintext",
                key="attack_plaintext",
                placeholder="11010111",
            )
        with c2:
            ciphertext_format = st.selectbox(
                "Ciphertext Format",
                ["Binary", "Decimal", "ASCII"],
                key="attack_ciphertext_format",
            )
            ciphertext_value = st.text_input(
                "Matching Ciphertext",
                key="attack_ciphertext",
                placeholder="10101000",
            )
        submitted = st.form_submit_button("Run Brute-Force Attack", use_container_width=True)

    if submitted:
        try:
            plaintext_binary = parse_input(plaintext_value, plaintext_format.lower())
            ciphertext_binary = parse_input(ciphertext_value, ciphertext_format.lower())
            result = brute_force_attack_unique(plaintext_binary, ciphertext_binary, verbose=True)
            attempts_df = build_bruteforce_attempts(plaintext_binary, ciphertext_binary)
            st.session_state.attack_result = {
                "plaintext_format": plaintext_format,
                "plaintext_raw": plaintext_value,
                "plaintext_binary": plaintext_binary,
                "ciphertext_format": ciphertext_format,
                "ciphertext_raw": ciphertext_value,
                "ciphertext_binary": ciphertext_binary,
                "result": result,
                "attempts_df": attempts_df,
                "result_text": build_attack_result_text(
                    plaintext_format,
                    plaintext_value,
                    plaintext_binary,
                    ciphertext_format,
                    ciphertext_value,
                    ciphertext_binary,
                    result,
                ),
            }
            st.session_state.attack_step_index = 0
            st.success("Brute-force analysis completed successfully.")
        except (TypeError, ValueError) as exc:
            st.error(f"Input error: {exc}")

    if "attack_result" not in st.session_state:
        st.info("Run the attack first to open the interactive attempt view.")
        return

    data = st.session_state.attack_result
    result = data["result"]
    attempts_df: pd.DataFrame = data["attempts_df"]
    matching_df = attempts_df[attempts_df["Match"]]

    a1, a2, a3 = st.columns(3)
    with a1:
        metric_card(
            "Known Plaintext",
            data["plaintext_binary"],
            "The fixed 8-bit plaintext tested with every candidate key.",
        )
    with a2:
        metric_card(
            "Expected Ciphertext",
            data["ciphertext_binary"],
            "The ciphertext that each produced value is compared against.",
        )
    with a3:
        key_status = result["unique_key"] if result.get("is_unique_match") else "Multiple candidates"
        metric_card(
            "Final Key Status",
            key_status,
            "A final key is shown only when the result is provably unique.",
        )

    m1, m2, m3 = st.columns(3)
    with m1:
        metric_card("Total Tested Keys", str(result["total_tested_keys"]))
    with m2:
        metric_card("Elapsed Time", f"{result['elapsed_time']:.6f}s")
    with m3:
        metric_card("Matching Key Count", str(len(matching_df)))

    if result.get("is_unique_match"):
        st.success(f"Unique matching key: {result['unique_key']}")
    else:
        st.warning(
            "This plaintext/ciphertext pair produced multiple valid candidate keys. "
            "The final key cannot be proven uniquely from this single pair."
        )

    if "attack_step_index" not in st.session_state:
        st.session_state.attack_step_index = 0
    attack_step_index = max(0, min(st.session_state.attack_step_index, len(attempts_df) - 1))
    st.session_state.attack_step_index = attack_step_index

    left, right = st.columns([0.95, 2.05], gap="large")
    with left:
        preview_titles = [
            f"{row['Candidate Key']} → {'MATCH' if row['Match'] else row['Produced Ciphertext']}"
            for _, row in attempts_df.head(12).iterrows()
        ]
        flow_panel(preview_titles, min(attack_step_index, len(preview_titles) - 1), title="Attack Flow")
        st.markdown(
            "<div class='mini-note'>The left panel previews the beginning of the exhaustive search. The full table is available on the right.</div>",
            unsafe_allow_html=True,
        )

    with right:
        n1, n2, n3 = st.columns([1, 1, 1.3])
        with n1:
            if st.button("← Previous Attempt", use_container_width=True, disabled=attack_step_index == 0):
                st.session_state.attack_step_index -= 1
                st.rerun()
        with n2:
            if st.button("Next Attempt →", use_container_width=True, disabled=attack_step_index == len(attempts_df) - 1):
                st.session_state.attack_step_index += 1
                st.rerun()
        with n3:
            jump_options = [1, 2, 3, 5, 10, 50, 100, 250, 500, 750, 1024]
            selected_jump = st.selectbox("Jump to step", jump_options, index=0)
            if st.button("Go", use_container_width=True):
                st.session_state.attack_step_index = selected_jump - 1
                st.rerun()

        current_attempt = attempts_df.iloc[attack_step_index].to_dict()
        st.markdown(
            f"""
            <div class="step-box">
                <div class="step-phase">Attack Step {current_attempt['Step']}</div>
                <div class="step-title">Candidate Key: {current_attempt['Candidate Key']}</div>
                <div class="step-desc">At each step, the plaintext is encrypted using the current candidate key. The produced ciphertext is then compared with the expected ciphertext. A match means the key is a valid candidate.</div>
                <div class="bitline">Produced = {current_attempt['Produced Ciphertext']} | Expected = {current_attempt['Expected Ciphertext']}</div>
            </div>
            """,
            unsafe_allow_html=True,
        )
        kv_block("Match", str(current_attempt["Match"]))
        kv_block("Candidate Key", str(current_attempt["Candidate Key"]))
        kv_block("Produced Ciphertext", str(current_attempt["Produced Ciphertext"]))
        kv_block("Expected Ciphertext", str(current_attempt["Expected Ciphertext"]))

    st.markdown("#### Full Attempt Table")
    show_only_matches = st.checkbox("Show only matching rows", value=False)
    if result.get("is_unique_match"):
        display_df = attempts_df[attempts_df["Candidate Key"] == result["unique_key"]]
    else:
        display_df = matching_df if show_only_matches else attempts_df
    st.dataframe(display_df, use_container_width=True, hide_index=True, height=420)

    st.markdown("#### Report Text")
    st.text_area("Copyable attack result", value=data["result_text"], height=260)
    show_download_button("sdes_bruteforce_result.txt", data["result_text"], "Download Attack Result")
    csv_data = attempts_df.to_csv(index=False).encode("utf-8")
    st.download_button(
        "Download Attack Table (CSV)",
        data=csv_data,
        file_name="sdes_bruteforce_attempts.csv",
        mime="text/csv",
        use_container_width=True,
    )


def render_differential_tab() -> None:
    hero(
        "Differential Analysis",
        "Differential Cryptanalysis — Pair and Frequency View",
        "Explore how one fixed plaintext XOR difference propagates through S-DES. This module shows a single pair example, a frequency experiment over many pairs, and optional S-box difference tables for report support.",
    )

    with st.form("differential_form"):
        c1, c2, c3 = st.columns(3)
        with c1:
            key_format = st.selectbox("Key Format", ["Binary", "Decimal"], key="diff_key_format")
        with c2:
            plaintext_format = st.selectbox("Plaintext Format", ["Binary", "Decimal", "ASCII"], key="diff_plaintext_format")
        with c3:
            sample_limit = st.selectbox("Sample Limit", [16, 32, 64, 128, 256], index=4, key="diff_sample_limit")

        key_value = st.text_input("Key", placeholder="Example: 1010000010", key="diff_key_value")
        plaintext_value = st.text_input("Reference Plaintext", placeholder="Example: 11010111", key="diff_plaintext_value")
        input_difference = st.text_input("Input Difference (8-bit ΔP)", placeholder="Example: 00000100", key="diff_input_difference")
        submitted = st.form_submit_button("Run Differential Analysis", use_container_width=True)

    if submitted:
        try:
            key_binary = parse_key_value(key_value, key_format)
            plaintext_binary = parse_input(plaintext_value, plaintext_format.lower())
            if len(input_difference.strip()) != 8 or set(input_difference.strip()) - {"0", "1"}:
                raise ValueError("Input Difference must be an 8-bit binary string.")
            input_difference_binary = input_difference.strip()

            pair_result = differential_pair_analysis(
                plaintext_binary, input_difference_binary, key_binary, verbose=False
            )
            experiment_result = differential_experiment(
                input_difference_binary, key_binary, sample_limit=sample_limit
            )
            s0_table = build_sbox_difference_table(S0)
            s1_table = build_sbox_difference_table(S1)

            st.session_state.differential_result = {
                "key_binary": key_binary,
                "plaintext_binary": plaintext_binary,
                "input_difference": input_difference_binary,
                "pair_result": pair_result,
                "experiment_result": experiment_result,
                "s0_table": s0_table,
                "s1_table": s1_table,
                "result_text": build_differential_result_text(
                    key_binary,
                    plaintext_binary,
                    input_difference_binary,
                    pair_result,
                    experiment_result,
                ),
            }
            st.success("Differential analysis completed successfully.")
        except (TypeError, ValueError) as exc:
            st.error(f"Input error: {exc}")

    if "differential_result" not in st.session_state:
        st.info("Run the differential analysis first to inspect pair behavior and difference frequencies.")
        return

    data = st.session_state.differential_result
    pair_result = data["pair_result"]
    experiment_result = data["experiment_result"]

    m1, m2, m3 = st.columns(3)
    with m1:
        metric_card("Input Difference ΔP", data["input_difference"], "Fixed XOR difference applied to the plaintext pair.")
    with m2:
        metric_card("Single-Pair ΔC", pair_result["output_difference"], "Observed ciphertext XOR difference for the selected pair.")
    with m3:
        metric_card(
            "Most Common ΔC",
            experiment_result["most_common_output_difference"],
            f"Observed {experiment_result['most_common_count']} time(s) in the frequency experiment.",
        )

    left, right = st.columns([1.05, 1.35], gap="large")
    with left:
        st.markdown("#### Single-Pair Differential View")
        kv_block("P1", pair_result["plaintext_1"])
        kv_block("P2 = P1 XOR ΔP", pair_result["plaintext_2"])
        kv_block("C1", pair_result["ciphertext_1"])
        kv_block("C2", pair_result["ciphertext_2"])
        kv_block("ΔP", pair_result["input_difference"])
        kv_block("ΔC", pair_result["output_difference"])

    with right:
        st.markdown("#### Output-Difference Frequency Table")
        st.dataframe(
            differential_frequency_df(experiment_result["frequency_table"]),
            use_container_width=True,
            hide_index=True,
            height=320,
        )

    st.markdown("#### Pair Experiment Table")
    st.dataframe(
        differential_pairs_df(experiment_result["pair_results"]),
        use_container_width=True,
        hide_index=True,
        height=360,
    )

    st.markdown("#### S-Box Difference Distribution Tables")
    s0_col, s1_col = st.columns(2)
    with s0_col:
        st.markdown("##### S0 Difference Table")
        st.dataframe(sbox_difference_df(data["s0_table"]), use_container_width=True, hide_index=True, height=320)
    with s1_col:
        st.markdown("##### S1 Difference Table")
        st.dataframe(sbox_difference_df(data["s1_table"]), use_container_width=True, hide_index=True, height=320)

    st.markdown("#### Differential Analysis Report Text")
    st.text_area("Copyable differential result", value=data["result_text"], height=260)
    show_download_button("sdes_differential_analysis.txt", data["result_text"], "Download Differential Result")


# -----------------------------------------------------------------------------
# Main
# -----------------------------------------------------------------------------


def main() -> None:
    configure_page()
    st.markdown(f"<div class='main-title'>{APP_TITLE}</div>", unsafe_allow_html=True)
    st.markdown(f"<div class='main-desc'>{APP_DESCRIPTION}</div>", unsafe_allow_html=True)
    render_reference_section()

    tab_single, tab_modes, tab_attack, tab_differential = st.tabs(
        ["Encrypt / Decrypt", "ECB / CBC / OFB", "Brute-force Attack", "Differential Cryptanalysis"]
    )

    with tab_single:
        render_single_block_tab()
    with tab_modes:
        render_modes_tab()
    with tab_attack:
        render_attack_tab()
    with tab_differential:
        render_differential_tab()


if __name__ == "__main__":
    main()
