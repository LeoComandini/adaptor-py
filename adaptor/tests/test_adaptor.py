import os
import unittest

from adaptor.adaptor import *
from adaptor.schnorr import *

def rand32():
    return int_from_bytes(os.urandom(32))

class TestsAdaptor(unittest.TestCase):

    def test_adaptor_ecdsa(self):
        x = 10
        y = 14
        message_hash = b'\xaa'*32
        Y = y * G
        X = x * G
        a = ecdsa_adaptor_encrypt(x, Y, message_hash)
        self.assertTrue(ecdsa_adaptor_verify(X, Y, message_hash, a))
        sig = ecdsa_adaptor_decrypt(a, y)
        y_recovered = ecdsa_adaptor_recover(Y, a, sig)
        self.assertEqual(y, y_recovered)

    def test_adaptor_schnorr(self):
        x = 10
        y = 14
        message_hash = b'\xaa'*32
        Y = y * G
        X = x * G
        a = schnorr_adaptor_encrypt(x, y, message_hash)
        self.assertTrue(schnorr_adaptor_verify(X, Y, message_hash, a))
        sig = schnorr_adaptor_decrypt(a, y)
        y_recovered = schnorr_adaptor_recover(Y, a, sig)
        self.assertEqual(y, y_recovered)

    def test_schnorr_atomic_swap(self):
        # Source: https://github.com/ElementsProject/scriptless-scripts/blob/master/md/atomic-swap.md
        # Warning: no formal security model or security proof.
        # FIXME: cannot aggregate signature in the naive way below
        #        parties need to agree on the used nonce
        #        implement musig module before this

        # Bob and Carl keypairs (b, B), (c, C)
        b = rand32()
        c = rand32()
        B = b * G
        C = c * G
        # Schnorr aggregate public key between Bob and Carl
        M = B + C

        # Bob sends coins to output O_b2c locked by B+C
        # Carl sends coins to output O_c2b locked by B+C
        # Bob constructs a transaction spending O_b2c, let m_b2c be the message
        # which must be signed to spend such transaction.
        # Bob constructs a transaction spending O_c2b, let m_c2b be the message
        # which must be signed to spend such transaction.
        m_b2c = b'\xb2' * 32
        m_c2b = b'\xc2' * 32

        # Bob and Carl create their nonces and agree on their aggregation
        # FIXME: nonce generation is broken
        Rb = rand32()
        Rc = rand32()
        R = Rb + Rc

        # Bob generates the encryption keypair, sends Y to Carl
        y = rand32()
        Y = y * G

        # Bob creates an adaptor signature for each message, sends them to Carl
        a_b2c = schnorr_adaptor_encrypt(b, y, m_b2c)
        a_c2b = schnorr_adaptor_encrypt(b, y, m_c2b)

        # Carl verifies the adaptor signatures
        self.assertTrue(schnorr_adaptor_verify(B, Y, m_b2c, a_b2c))
        self.assertTrue(schnorr_adaptor_verify(B, Y, m_c2b, a_c2b))

        # FIXME: which R ?
        # Carl signs m_c2b
        sig_c2b_c = schnorr_sign(c, m_c2b)

        # Bob signs m_c2b
        sig_c2b_b = schnorr_sign(b, m_c2b)
        # Bob can obtain a valid signature for m_c2b
        sig_c2b = sig_c2b_b + sig_c2b_c
        self.assertTrue(schnorr_verify(M, m_c2b, sig_c2b))

        # Bob published the signature to spend the coin

        # Carl sees sig_c2b, thus it can compute s_c2b_b by difference
        # Carl can recover the decryption key y
        # FIXME: Y is not used
        y_recovered = schnorr_adaptor_recover(Y, a_c2b, sig_c2b_b)
        self.assertEqual(y, y_recovered)

        # Carl can decrypt the other adaptor signature with the receovered key
        sig_b2c_b = schnorr_adaptor_decrypt(a_b2c, y_recovered)
        # Carl can obtain a valid signature for m_b2c
        sig_b2c_c = schnorr_sign(c, m_b2c)
        sig_b2c = sig_b2c_b + sig_b2c_c
        self.assertTrue(schnorr_verify(M, m_b2c, sig_b2c))

        # Carl can finally publish the signature to complete the swap
