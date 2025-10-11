"""
Modified AES Implementation

This module implements a modified AES variant with:
- Fixed alternative S-box (S2) constructed as S2(x) = S(bit_reverse8(x))
- Fixed alternative ShiftRows using offsets (0, 1, 3, 1)
- Unchanged MixColumns and round structure
- Support for 128/192/256-bit keys

The modified variant is static (no dynamic S-box or ShiftRows).
"""

from standard_aes import (
    s_box, mix_columns, inv_mix_columns, add_round_key,
    bytes2matrix, matrix2bytes, xor_bytes, r_con, AES,
    pad, unpad, split_blocks, inc_bytes
)


def bit_reverse8(x):
    """Reverse the 8 bits of a byte."""
    result = 0
    for i in range(8):
        result = (result << 1) | ((x >> i) & 1)
    return result


# Generate the modified S-box: S2(x) = S(bit_reverse8(x))
s_box2 = tuple(s_box[bit_reverse8(i)] for i in range(256))

# Generate the inverse S-box for S2
inv_s_box2 = [0] * 256
for i in range(256):
    inv_s_box2[s_box2[i]] = i
inv_s_box2 = tuple(inv_s_box2)

# Fixed ShiftRows offsets (different from standard AES which uses 0,1,2,3)
SHIFT_OFFSETS = (0, 1, 3, 1)


def sub_bytes2(s):
    """SubBytes using the modified S-box."""
    for i in range(4):
        for j in range(4):
            s[i][j] = s_box2[s[i][j]]


def inv_sub_bytes2(s):
    """Inverse SubBytes using the modified inverse S-box."""
    for i in range(4):
        for j in range(4):
            s[i][j] = inv_s_box2[s[i][j]]


def shift_rows2(s):
    """
    Modified ShiftRows with offsets (0, 1, 3, 1).
    State is column-major: s[col][row]
    For each row, rotate the 4 values across columns.
    """
    # Row 0: no rotation (offset 0)
    # Row 1: rotate left by 1 (offset 1)
    s[0][1], s[1][1], s[2][1], s[3][1] = s[1][1], s[2][1], s[3][1], s[0][1]
    # Row 2: rotate left by 3 (offset 3)
    s[0][2], s[1][2], s[2][2], s[3][2] = s[3][2], s[0][2], s[1][2], s[2][2]
    # Row 3: rotate left by 1 (offset 1)
    s[0][3], s[1][3], s[2][3], s[3][3] = s[1][3], s[2][3], s[3][3], s[0][3]


def inv_shift_rows2(s):
    """
    Inverse of modified ShiftRows.
    Rotate right by the same offsets (equivalent to rotate left by 4-offset).
    """
    # Row 0: no rotation (offset 0)
    # Row 1: rotate right by 1 (same as left by 3)
    s[0][1], s[1][1], s[2][1], s[3][1] = s[3][1], s[0][1], s[1][1], s[2][1]
    # Row 2: rotate right by 3 (same as left by 1)
    s[0][2], s[1][2], s[2][2], s[3][2] = s[1][2], s[2][2], s[3][2], s[0][2]
    # Row 3: rotate right by 1 (same as left by 3)
    s[0][3], s[1][3], s[2][3], s[3][3] = s[3][3], s[0][3], s[1][3], s[2][3]


class AESMod:
    """
    Modified AES class with alternative S-box and ShiftRows.
    
    Supports 128/192/256-bit keys with modified S-box in key expansion.
    Provides block encryption/decryption and various modes.
    """
    rounds_by_key_size = {16: 10, 24: 12, 32: 14}
    
    def __init__(self, master_key):
        """
        Initializes the object with a given key.
        """
        assert len(master_key) in AESMod.rounds_by_key_size
        self.n_rounds = AESMod.rounds_by_key_size[len(master_key)]
        self._key_matrices = self._expand_key(master_key)
    
    def _expand_key(self, master_key):
        """
        Expands and returns a list of key matrices for the given master_key.
        Uses the modified S-box (s_box2) in the key schedule.
        """
        # Initialize round keys with raw key material.
        key_columns = bytes2matrix(master_key)
        iteration_size = len(master_key) // 4
        
        i = 1
        while len(key_columns) < (self.n_rounds + 1) * 4:
            # Copy previous word.
            word = list(key_columns[-1])
            
            # Perform schedule_core once every "row".
            if len(key_columns) % iteration_size == 0:
                # Circular shift.
                word.append(word.pop(0))
                # Map to modified S-BOX.
                word = [s_box2[b] for b in word]
                # XOR with first byte of R-CON, since the others bytes of R-CON are 0.
                word[0] ^= r_con[i]
                i += 1
            elif len(master_key) == 32 and len(key_columns) % iteration_size == 4:
                # Run word through modified S-box in the fourth iteration when using a
                # 256-bit key.
                word = [s_box2[b] for b in word]
            
            # XOR with equivalent word from previous iteration.
            word = xor_bytes(word, key_columns[-iteration_size])
            key_columns.append(word)
        
        # Group key words in 4x4 byte matrices.
        return [key_columns[4*i : 4*(i+1)] for i in range(len(key_columns) // 4)]
    
    def encrypt_block(self, plaintext):
        """
        Encrypts a single block of 16 byte long plaintext.
        """
        assert len(plaintext) == 16
        
        plain_state = bytes2matrix(plaintext)
        
        add_round_key(plain_state, self._key_matrices[0])
        
        for i in range(1, self.n_rounds):
            sub_bytes2(plain_state)
            shift_rows2(plain_state)
            mix_columns(plain_state)
            add_round_key(plain_state, self._key_matrices[i])
        
        sub_bytes2(plain_state)
        shift_rows2(plain_state)
        add_round_key(plain_state, self._key_matrices[-1])
        
        return matrix2bytes(plain_state)
    
    def decrypt_block(self, ciphertext):
        """
        Decrypts a single block of 16 byte long ciphertext.
        """
        assert len(ciphertext) == 16
        
        cipher_state = bytes2matrix(ciphertext)
        
        add_round_key(cipher_state, self._key_matrices[-1])
        inv_shift_rows2(cipher_state)
        inv_sub_bytes2(cipher_state)
        
        for i in range(self.n_rounds - 1, 0, -1):
            add_round_key(cipher_state, self._key_matrices[i])
            inv_mix_columns(cipher_state)
            inv_shift_rows2(cipher_state)
            inv_sub_bytes2(cipher_state)
        
        add_round_key(cipher_state, self._key_matrices[0])
        
        return matrix2bytes(cipher_state)
    
    def encrypt_cbc(self, plaintext, iv):
        """
        Encrypts `plaintext` using CBC mode and PKCS#7 padding, with the given
        initialization vector (iv).
        """
        assert len(iv) == 16
        
        plaintext = pad(plaintext)
        
        blocks = []
        previous = iv
        for plaintext_block in split_blocks(plaintext):
            # CBC mode encrypt: encrypt(plaintext_block XOR previous)
            block = self.encrypt_block(xor_bytes(plaintext_block, previous))
            blocks.append(block)
            previous = block
        
        return b''.join(blocks)
    
    def decrypt_cbc(self, ciphertext, iv):
        """
        Decrypts `ciphertext` using CBC mode and PKCS#7 padding, with the given
        initialization vector (iv).
        """
        assert len(iv) == 16
        
        blocks = []
        previous = iv
        for ciphertext_block in split_blocks(ciphertext):
            # CBC mode decrypt: previous XOR decrypt(ciphertext)
            blocks.append(xor_bytes(previous, self.decrypt_block(ciphertext_block)))
            previous = ciphertext_block
        
        return unpad(b''.join(blocks))
    
    def encrypt_cfb(self, plaintext, iv):
        """
        Encrypts `plaintext` using CFB mode with the given initialization vector (iv).
        """
        assert len(iv) == 16
        
        blocks = []
        prev_ciphertext = iv
        for plaintext_block in split_blocks(plaintext, require_padding=False):
            # CFB mode encrypt: plaintext_block XOR encrypt(prev_ciphertext)
            ciphertext_block = xor_bytes(plaintext_block, self.encrypt_block(prev_ciphertext))
            blocks.append(ciphertext_block)
            prev_ciphertext = ciphertext_block
        
        return b''.join(blocks)
    
    def decrypt_cfb(self, ciphertext, iv):
        """
        Decrypts `ciphertext` using CFB mode with the given initialization vector (iv).
        """
        assert len(iv) == 16
        
        blocks = []
        prev_ciphertext = iv
        for ciphertext_block in split_blocks(ciphertext, require_padding=False):
            # CFB mode decrypt: ciphertext XOR encrypt(prev_ciphertext)
            plaintext_block = xor_bytes(ciphertext_block, self.encrypt_block(prev_ciphertext))
            blocks.append(plaintext_block)
            prev_ciphertext = ciphertext_block
        
        return b''.join(blocks)
    
    def encrypt_ofb(self, plaintext, iv):
        """
        Encrypts `plaintext` using OFB mode with the given initialization vector (iv).
        """
        assert len(iv) == 16
        
        blocks = []
        previous = iv
        for plaintext_block in split_blocks(plaintext, require_padding=False):
            # OFB mode encrypt: plaintext_block XOR encrypt(previous)
            block = self.encrypt_block(previous)
            ciphertext_block = xor_bytes(plaintext_block, block)
            blocks.append(ciphertext_block)
            previous = block
        
        return b''.join(blocks)
    
    def decrypt_ofb(self, ciphertext, iv):
        """
        Decrypts `ciphertext` using OFB mode with the given initialization vector (iv).
        """
        assert len(iv) == 16
        
        blocks = []
        previous = iv
        for ciphertext_block in split_blocks(ciphertext, require_padding=False):
            # OFB mode decrypt: ciphertext XOR encrypt(previous)
            block = self.encrypt_block(previous)
            plaintext_block = xor_bytes(ciphertext_block, block)
            blocks.append(plaintext_block)
            previous = block
        
        return b''.join(blocks)
    
    def encrypt_ctr(self, plaintext, iv):
        """
        Encrypts `plaintext` using CTR mode with the given nonce/IV.
        """
        assert len(iv) == 16
        
        blocks = []
        nonce = iv
        for plaintext_block in split_blocks(plaintext, require_padding=False):
            # CTR mode encrypt: plaintext_block XOR encrypt(nonce)
            block = xor_bytes(plaintext_block, self.encrypt_block(nonce))
            blocks.append(block)
            nonce = inc_bytes(nonce)
        
        return b''.join(blocks)
    
    def decrypt_ctr(self, ciphertext, iv):
        """
        Decrypts `ciphertext` using CTR mode with the given nonce/IV.
        """
        assert len(iv) == 16
        
        blocks = []
        nonce = iv
        for ciphertext_block in split_blocks(ciphertext, require_padding=False):
            # CTR mode decrypt: ciphertext XOR encrypt(nonce)
            block = xor_bytes(ciphertext_block, self.encrypt_block(nonce))
            blocks.append(block)
            nonce = inc_bytes(nonce)
        
        return b''.join(blocks)


__all__ = ["AESMod", "s_box2", "inv_s_box2"]
