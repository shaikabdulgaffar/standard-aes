"""
Tests for Modified AES Implementation

Tests the AESMod class with:
- Block round-trip tests for 128/192/256-bit keys
- Mode tests (CBC, CFB, OFB, CTR) with round-trip verification
- Random message and key testing
"""

import unittest
import os
from aes_mod import AESMod


class TestModBlock(unittest.TestCase):
    """
    Tests raw AESMod-128 block operations.
    """
    def setUp(self):
        self.aes = AESMod(b'\x00' * 16)
    
    def test_success(self):
        """ Should be able to encrypt and decrypt block messages. """
        message = b'\x01' * 16
        ciphertext = self.aes.encrypt_block(message)
        self.assertEqual(self.aes.decrypt_block(ciphertext), message)
        
        message = b'a secret message'
        ciphertext = self.aes.encrypt_block(message)
        self.assertEqual(self.aes.decrypt_block(ciphertext), message)
    
    def test_bad_key(self):
        """ AESMod requires keys of an exact size. """
        with self.assertRaises(AssertionError):
            AESMod(b'short key')
        
        with self.assertRaises(AssertionError):
            AESMod(b'long key' * 10)
    
    def test_different_from_standard(self):
        """ Modified AES should produce different ciphertext than standard AES. """
        from standard_aes import AES
        
        key = b'\x2B\x7E\x15\x16\x28\xAE\xD2\xA6\xAB\xF7\x15\x88\x09\xCF\x4F\x3C'
        message = b'\x32\x43\xF6\xA8\x88\x5A\x30\x8D\x31\x31\x98\xA2\xE0\x37\x07\x34'
        
        aes_standard = AES(key)
        aes_modified = AESMod(key)
        
        ciphertext_standard = aes_standard.encrypt_block(message)
        ciphertext_modified = aes_modified.encrypt_block(message)
        
        # They should be different since we use different S-box and ShiftRows
        self.assertNotEqual(ciphertext_standard, ciphertext_modified)
        
        # But each should decrypt correctly
        self.assertEqual(aes_standard.decrypt_block(ciphertext_standard), message)
        self.assertEqual(aes_modified.decrypt_block(ciphertext_modified), message)


class TestModKeySizes(unittest.TestCase):
    """
    Tests encrypt and decryption using 192- and 256-bit keys.
    """
    def test_192(self):
        aes = AESMod(b'P' * 24)
        message = b'M' * 16
        ciphertext = aes.encrypt_block(message)
        self.assertEqual(aes.decrypt_block(ciphertext), message)
    
    def test_256(self):
        aes = AESMod(b'P' * 32)
        message = b'M' * 16
        ciphertext = aes.encrypt_block(message)
        self.assertEqual(aes.decrypt_block(ciphertext), message)
    
    def test_random_keys_128(self):
        """ Test with random 128-bit keys and messages. """
        for _ in range(10):
            key = os.urandom(16)
            message = os.urandom(16)
            aes = AESMod(key)
            ciphertext = aes.encrypt_block(message)
            self.assertEqual(aes.decrypt_block(ciphertext), message)
    
    def test_random_keys_192(self):
        """ Test with random 192-bit keys and messages. """
        for _ in range(10):
            key = os.urandom(24)
            message = os.urandom(16)
            aes = AESMod(key)
            ciphertext = aes.encrypt_block(message)
            self.assertEqual(aes.decrypt_block(ciphertext), message)
    
    def test_random_keys_256(self):
        """ Test with random 256-bit keys and messages. """
        for _ in range(10):
            key = os.urandom(32)
            message = os.urandom(16)
            aes = AESMod(key)
            ciphertext = aes.encrypt_block(message)
            self.assertEqual(aes.decrypt_block(ciphertext), message)


class TestModCbc(unittest.TestCase):
    """
    Tests AESMod in CBC mode.
    """
    def setUp(self):
        self.aes = AESMod(b'\x00' * 16)
        self.iv = b'\x01' * 16
        self.message = b'my message'
    
    def test_single_block(self):
        """ Should be able to encrypt and decrypt single block messages. """
        ciphertext = self.aes.encrypt_cbc(self.message, self.iv)
        self.assertEqual(self.aes.decrypt_cbc(ciphertext, self.iv), self.message)
        
        # Since len(message) < block size, padding won't create a new block.
        self.assertEqual(len(ciphertext), 16)
    
    def test_wrong_iv(self):
        """ CBC mode should verify the IVs are of correct length."""
        with self.assertRaises(AssertionError):
            self.aes.encrypt_cbc(self.message, b'short iv')
        
        with self.assertRaises(AssertionError):
            self.aes.encrypt_cbc(self.message, b'long iv' * 16)
    
    def test_different_iv(self):
        """ Different IVs should generate different ciphertexts. """
        iv2 = b'\x02' * 16
        
        ciphertext1 = self.aes.encrypt_cbc(self.message, self.iv)
        ciphertext2 = self.aes.encrypt_cbc(self.message, iv2)
        self.assertNotEqual(ciphertext1, ciphertext2)
        
        plaintext1 = self.aes.decrypt_cbc(ciphertext1, self.iv)
        plaintext2 = self.aes.decrypt_cbc(ciphertext2, iv2)
        self.assertEqual(plaintext1, plaintext2)
        self.assertEqual(plaintext1, self.message)
    
    def test_whole_block_padding(self):
        """ When len(message) == block size, padding will add a block. """
        block_message = b'M' * 16
        ciphertext = self.aes.encrypt_cbc(block_message, self.iv)
        self.assertEqual(len(ciphertext), 32)
        self.assertEqual(self.aes.decrypt_cbc(ciphertext, self.iv), block_message)
    
    def test_long_message(self):
        """ CBC should allow for messages longer than a single block. """
        long_message = b'M' * 100
        ciphertext = self.aes.encrypt_cbc(long_message, self.iv)
        self.assertEqual(self.aes.decrypt_cbc(ciphertext, self.iv), long_message)


class TestModCfb(unittest.TestCase):
    """
    Tests AESMod in CFB mode.
    """
    def setUp(self):
        self.aes = AESMod(b'\x00' * 16)
        self.iv = b'\x01' * 16
        self.message = b'my message'
    
    def test_single_block(self):
        """ Should be able to encrypt and decrypt single block messages. """
        ciphertext = self.aes.encrypt_cfb(self.message, self.iv)
        self.assertEqual(self.aes.decrypt_cfb(ciphertext, self.iv), self.message)
        self.assertEqual(len(ciphertext), len(self.message))
    
    def test_wrong_iv(self):
        """ CFB mode should verify the IVs are of correct length."""
        with self.assertRaises(AssertionError):
            self.aes.encrypt_cfb(self.message, b'short iv')
    
    def test_different_iv(self):
        """ Different IVs should generate different ciphertexts. """
        iv2 = b'\x02' * 16
        
        ciphertext1 = self.aes.encrypt_cfb(self.message, self.iv)
        ciphertext2 = self.aes.encrypt_cfb(self.message, iv2)
        self.assertNotEqual(ciphertext1, ciphertext2)
        
        plaintext1 = self.aes.decrypt_cfb(ciphertext1, self.iv)
        plaintext2 = self.aes.decrypt_cfb(ciphertext2, iv2)
        self.assertEqual(plaintext1, plaintext2)
        self.assertEqual(plaintext1, self.message)
    
    def test_whole_block_padding(self):
        block_message = b'M' * 16
        ciphertext = self.aes.encrypt_cfb(block_message, self.iv)
        self.assertEqual(len(ciphertext), len(block_message))
        self.assertEqual(self.aes.decrypt_cfb(ciphertext, self.iv), block_message)
    
    def test_long_message(self):
        long_message = b'M' * 100
        ciphertext = self.aes.encrypt_cfb(long_message, self.iv)
        self.assertEqual(self.aes.decrypt_cfb(ciphertext, self.iv), long_message)


class TestModOfb(unittest.TestCase):
    """
    Tests AESMod in OFB mode.
    """
    def setUp(self):
        self.aes = AESMod(b'\x00' * 16)
        self.iv = b'\x01' * 16
        self.message = b'my message'
    
    def test_single_block(self):
        """ Should be able to encrypt and decrypt single block messages. """
        ciphertext = self.aes.encrypt_ofb(self.message, self.iv)
        self.assertEqual(self.aes.decrypt_ofb(ciphertext, self.iv), self.message)
        self.assertEqual(len(ciphertext), len(self.message))
    
    def test_wrong_iv(self):
        """ OFB mode should verify the IVs are of correct length."""
        with self.assertRaises(AssertionError):
            self.aes.encrypt_ofb(self.message, b'short iv')
    
    def test_different_iv(self):
        """ Different IVs should generate different ciphertexts. """
        iv2 = b'\x02' * 16
        
        ciphertext1 = self.aes.encrypt_ofb(self.message, self.iv)
        ciphertext2 = self.aes.encrypt_ofb(self.message, iv2)
        self.assertNotEqual(ciphertext1, ciphertext2)
        
        plaintext1 = self.aes.decrypt_ofb(ciphertext1, self.iv)
        plaintext2 = self.aes.decrypt_ofb(ciphertext2, iv2)
        self.assertEqual(plaintext1, plaintext2)
        self.assertEqual(plaintext1, self.message)
    
    def test_long_message(self):
        long_message = b'M' * 100
        ciphertext = self.aes.encrypt_ofb(long_message, self.iv)
        self.assertEqual(self.aes.decrypt_ofb(ciphertext, self.iv), long_message)


class TestModCtr(unittest.TestCase):
    """
    Tests AESMod in CTR mode.
    """
    def setUp(self):
        self.aes = AESMod(b'\x00' * 16)
        self.iv = b'\x01' * 16
        self.message = b'my message'
    
    def test_single_block(self):
        """ Should be able to encrypt and decrypt single block messages. """
        ciphertext = self.aes.encrypt_ctr(self.message, self.iv)
        self.assertEqual(self.aes.decrypt_ctr(ciphertext, self.iv), self.message)
        
        # Stream mode ciphers don't increase message size.
        self.assertEqual(len(ciphertext), len(self.message))
    
    def test_wrong_iv(self):
        """ CTR mode should verify the IVs are of correct length."""
        with self.assertRaises(AssertionError):
            self.aes.encrypt_ctr(self.message, b'short iv')
    
    def test_different_iv(self):
        """ Different IVs should generate different ciphertexts. """
        iv2 = b'\x02' * 16
        
        ciphertext1 = self.aes.encrypt_ctr(self.message, self.iv)
        ciphertext2 = self.aes.encrypt_ctr(self.message, iv2)
        self.assertNotEqual(ciphertext1, ciphertext2)
        
        plaintext1 = self.aes.decrypt_ctr(ciphertext1, self.iv)
        plaintext2 = self.aes.decrypt_ctr(ciphertext2, iv2)
        self.assertEqual(plaintext1, plaintext2)
        self.assertEqual(plaintext1, self.message)
    
    def test_whole_block_padding(self):
        block_message = b'M' * 16
        ciphertext = self.aes.encrypt_ctr(block_message, self.iv)
        self.assertEqual(len(ciphertext), len(block_message))
        self.assertEqual(self.aes.decrypt_ctr(ciphertext, self.iv), block_message)
    
    def test_long_message(self):
        long_message = b'M' * 100
        ciphertext = self.aes.encrypt_ctr(long_message, self.iv)
        self.assertEqual(self.aes.decrypt_ctr(ciphertext, self.iv), long_message)


def run():
    unittest.main()


if __name__ == '__main__':
    run()
