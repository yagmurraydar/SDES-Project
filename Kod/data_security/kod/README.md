# S-DES Data Security Project

## Project Description

This repository contains a university Data Security project on **S-DES (Simplified Data Encryption Standard)**. The project includes a manual Python implementation of the S-DES algorithm, a Streamlit-based interactive web interface, validation tests, and helper functions for basic security analysis.

The main goal of the project is to demonstrate how S-DES works at the bit level, including key generation, permutation operations, encryption and decryption rounds, block cipher modes, brute-force analysis, and differential cryptanalysis experiments. The implementation is intended for academic study and presentation purposes.

## Features

- Manual implementation of the S-DES core algorithm
- S-DES constants and permutation tables:
  - `P10`
  - `P8`
  - `P4`
  - `IP`
  - `IP^-1`
  - `EP`
- S-box definitions for `S0` and `S1`
- Input validation for binary keys, blocks, and initialization vectors
- Low-level bit operations:
  - permutation
  - left shift
  - XOR
  - split and join operations
- Key scheduling and subkey generation:
  - `K1`
  - `K2`
- Single-block encryption and decryption
- Block cipher modes:
  - ECB
  - CBC
  - OFB
- Streamlit web interface with multiple interactive tabs
- Step-by-step encryption and decryption visualization
- Brute-force known-plaintext attack support
- Differential cryptanalysis helper functions
- S-box difference distribution table generation
- Report-friendly validation output
- Downloadable text outputs from the web interface

## Technologies Used

- **Python** for the core S-DES implementation
- **Streamlit** for the interactive web interface
- **pandas** for displaying tabular data in the interface

The backend S-DES logic is implemented manually and does not rely on ready-made cryptography libraries for the S-DES core algorithm.

## Quick Start

```bash
pip install streamlit pandas
streamlit run gui_app.py
```

To run the validation script:

```bash
python test_sdes_core.py
```

## Project Structure

The project is organized around three main Python files:

- `sdes_core.py` contains the S-DES algorithm, block cipher modes, attack utilities, and differential cryptanalysis helpers.
- `gui_app.py` contains the Streamlit interface used for interactive demonstration.
- `test_sdes_core.py` contains validation tests and report-friendly output.

## Repository Layout

```text
.
├── README.md
├── README_TR.md
├── gui_app.py
├── sdes_core.py
├── test_sdes_core.py
└── data_securityUML.drawio
```

## Requirements / Prerequisites

Before running the project, make sure the following are installed:

- Python 3.x
- `pip`
- Streamlit
- pandas

The project can be run locally from the command line. No cloud deployment or external cryptographic service is required.

## Installation

1. Clone or download the repository.

2. Open a terminal in the project directory.

3. Install the required dependencies:

```bash
pip install streamlit pandas
```

## How to Run

### Run the Streamlit Application

```bash
streamlit run gui_app.py
```

After running this command, Streamlit will start a local web server and provide a local URL in the terminal.

### Run the Test Script

```bash
python test_sdes_core.py
```

The test script prints expected values, actual values, and pass/fail results in a format suitable for inclusion in a report or project demonstration.

## Sample Commands

```bash
# Install dependencies
pip install streamlit pandas

# Start the interactive web interface
streamlit run gui_app.py

# Run validation and demonstration tests
python test_sdes_core.py
```

## Usage

The Streamlit interface is divided into several practical sections for demonstration and analysis.

### Encrypt / Decrypt Tab

This tab allows users to perform single-block S-DES encryption and decryption. It includes:

- input fields for an 8-bit plaintext or ciphertext block
- input field for a 10-bit key
- generated subkeys `K1` and `K2`
- step-by-step visualization of the S-DES process
- intermediate permutation, S-box, and round values
- final encrypted or decrypted output

This section is useful for explaining the internal structure of S-DES during a presentation.

### ECB / CBC / OFB Mode Tab

This tab supports multi-block encryption and decryption using common block cipher modes:

- **ECB (Electronic Codebook):** processes each block independently
- **CBC (Cipher Block Chaining):** uses an initialization vector and chaining between blocks
- **OFB (Output Feedback):** generates a keystream using feedback from the cipher output

Users can enter multiple 8-bit blocks, select a mode, provide the required key and initialization vector when needed, and view the resulting block outputs.

### Brute-force Attack Tab

This tab demonstrates known-plaintext brute-force analysis against the small S-DES key space. Users can provide plaintext and ciphertext pairs and search for candidate 10-bit keys.

Because S-DES uses a very small key size, exhaustive key search is computationally feasible and useful for educational demonstration.

### Differential Cryptanalysis Tab

This tab provides helper tools for differential cryptanalysis experiments, including:

- differential pair analysis
- differential experiment execution
- S-box difference distribution table generation

These tools help illustrate how input differences may influence output differences in simplified block cipher structures.

### Reference Tables

The interface also displays visible S-DES reference information such as:

- permutation tables
- expansion/permutation tables
- S-box tables

These tables support step-by-step learning and make the interface suitable for a classroom demonstration.

## Example Test Vectors

The validation script includes sample S-DES-style test vectors that can be used to verify the implementation:

```text
Key:        1010000010
Plaintext:  11010111
K1:         10100100
K2:         01000011
Ciphertext: 10101000
```

These values are used by `test_sdes_core.py` to compare expected and actual results. Additional examples can be generated through the Streamlit interface.

## Validation and Testing

The file `test_sdes_core.py` validates important parts of the implementation, including:

- input validation checks
- helper function behavior
- permutation operations
- S-box lookup behavior
- subkey generation
- encryption and decryption correctness
- differential cryptanalysis helper behavior
- verbose decryption trace output for demonstration

The script prints results in a pass/fail format, making it suitable for project reports and live demonstrations.

Run the tests with:

```bash
python test_sdes_core.py
```

## Security Analysis

This project includes basic security analysis features for educational purposes.

### Brute-force Analysis

S-DES uses a 10-bit key, so the full key space contains only 1024 possible keys. The project includes brute-force utilities that can search this key space using known plaintext and ciphertext pairs.

This demonstrates why small key sizes are insecure and why modern cryptographic systems require significantly larger key spaces.

### Differential Cryptanalysis

The project also includes helper functions for differential cryptanalysis, including S-box difference distribution table generation and differential pair experiments.

These features are intended to support conceptual analysis of how differences in input blocks propagate through simplified cipher components.

## Notes / Limitations

- S-DES is an educational algorithm and is not secure for real-world use.
- The implementation is designed for learning, testing, and presentation.
- The project should not be used to protect sensitive data.
- The Streamlit interface is intended for local demonstration.
- The brute-force and differential cryptanalysis features are simplified for academic study.
- The implementation focuses on clarity and traceability rather than industrial performance.

## Optional Future Improvements

Possible future extensions include:

- adding more predefined test vectors
- exporting full step-by-step traces as structured report files
- adding visual diagrams for Feistel rounds
- improving multi-block input formatting options
- adding more detailed explanations for differential cryptanalysis outputs
- expanding automated tests for ECB, CBC, and OFB modes

## License

For academic use.

## Authors

- Student Name 1
- Student Name 2
- Student Name 3

