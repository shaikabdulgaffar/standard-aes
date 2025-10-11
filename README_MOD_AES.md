# Modified AES Variant

This document describes the modified AES variant implemented in `aes_mod.py`.

## Overview

The modified AES variant implements a static (non-dynamic) modification to the standard AES cipher by using:

1. **Fixed Alternative S-box (S2)**: A different substitution box constructed as `S2(x) = S(bit_reverse8(x))`
2. **Fixed Alternative ShiftRows**: Using rotation offsets `(0, 1, 3, 1)` instead of the standard `(0, 1, 2, 3)`
3. **Unchanged MixColumns and round structure**: The core structure remains the same as standard AES

## Design Decisions

### Modified S-box (S2)

The modified S-box is constructed by applying a bit-reversal transformation to the input before looking up in the standard AES S-box:

```
S2(x) = S(bit_reverse8(x))
```

Where `bit_reverse8(x)` reverses the 8 bits of the input byte. For example:
- Input: `0b10110001` → `0b10001101`

This construction:
- Is a fixed, affine-equivalent reindexing on the input side
- Yields a different static S-box table
- Preserves core cryptographic parameters (invertibility, DU=4, NL=112, degree=7)
- Does **not** involve any dynamic or key-dependent behavior

The inverse S-box `inv_s_box2` is computed programmatically from `s_box2` to ensure consistency.

### Modified ShiftRows

The modified ShiftRows uses fixed rotation offsets different from standard AES:

- **Row 0**: No rotation (offset 0) - same as standard
- **Row 1**: Rotate left by 1 (offset 1) - same as standard
- **Row 2**: Rotate left by 3 (offset 3) - **different** from standard (which uses 2)
- **Row 3**: Rotate left by 1 (offset 1) - **different** from standard (which uses 3)

This pattern `(0, 1, 3, 1)` increases diffusion in a different alignment compared to standard AES.

The inverse operation `inv_shift_rows2` rotates right by the same offsets.

### Key Schedule

The key expansion uses the modified S-box `S2` in the SubWord operation, just as standard AES uses the standard S-box `S`. This ensures the round keys are derived consistently with the modified cipher.

### Modes of Operation

The implementation supports the same modes as the standard AES:
- **CBC** (Cipher Block Chaining) - with PKCS#7 padding
- **CFB** (Cipher Feedback) - without padding
- **OFB** (Output Feedback) - without padding
- **CTR** (Counter) - without padding

## Key Sizes

The modified AES supports the same key sizes as standard AES:
- **128-bit keys** (16 bytes) - 10 rounds
- **192-bit keys** (24 bytes) - 12 rounds
- **256-bit keys** (32 bytes) - 14 rounds

## Security Characteristics

- **Static S-box**: The S-box is fixed at implementation time, not dynamic or key-dependent
- **Static ShiftRows**: The rotation pattern is fixed, not dynamic
- **Constant-time**: Uses table lookups only; no branches on secret data
- **Invertible**: Decrypt is the exact inverse of encrypt

## Usage

### Basic Block Encryption

```python
from aes_mod import AESMod

# Create AESMod instance with a key
key = b'sixteen byte key'  # 128-bit key
aes = AESMod(key)

# Encrypt a 16-byte block
plaintext = b'Hello, World!!!!'
ciphertext = aes.encrypt_block(plaintext)

# Decrypt the block
decrypted = aes.decrypt_block(ciphertext)
assert decrypted == plaintext
```

### CBC Mode

```python
# CBC mode with initialization vector
iv = b'sixteen byte IV!'
plaintext = b'This is a longer message that spans multiple blocks.'

ciphertext = aes.encrypt_cbc(plaintext, iv)
decrypted = aes.decrypt_cbc(ciphertext, iv)
assert decrypted == plaintext
```

### Other Modes

```python
# CFB mode
ciphertext = aes.encrypt_cfb(plaintext, iv)
decrypted = aes.decrypt_cfb(ciphertext, iv)

# OFB mode
ciphertext = aes.encrypt_ofb(plaintext, iv)
decrypted = aes.decrypt_ofb(ciphertext, iv)

# CTR mode
ciphertext = aes.encrypt_ctr(plaintext, iv)
decrypted = aes.decrypt_ctr(ciphertext, iv)
```

## Running Tests

To run the tests for the modified AES variant:

```bash
python tests_modified.py
```

To run all tests (standard and modified):

```bash
python standard_tests.py
python tests_modified.py
```

## Differences from Standard AES

The modified variant produces **different ciphertext** from standard AES for the same plaintext and key, because:

1. The S-box values are different (due to bit-reversal transformation)
2. The ShiftRows offsets are different (especially for rows 2 and 3)

However, both variants:
- Support the same key sizes (128/192/256 bits)
- Use the same round structure
- Use the same MixColumns operation
- Guarantee that decrypt is the inverse of encrypt

## Implementation Notes

- The state layout is column-major: `state[column][row]`
- ShiftRows rotates elements at a row index across all 4 columns
- The modified S-box is precomputed at import time for efficiency
- The inverse S-box is computed programmatically from the forward S-box
- Utilities like `bytes2matrix`, `matrix2bytes`, `xor_bytes`, etc. are reused from `standard_aes.py`
