import unittest

from adaptor.adaptor import *

class TestsAdaptor(unittest.TestCase):

    def test_adaptor(self):
        x = 10
        y = 14
        message_hash = b'\xaa'*32
        Y = y * G
        X = x * G
        R = x * Y
        a = ecdsa_adaptor_encrypt(x, Y, message_hash)
        self.assertTrue(ecdsa_adaptor_verify(X, Y, message_hash, a))
        sig = ecdsa_adaptor_decrypt(a, y)
        y_recovered = ecdsa_adaptor_recover(Y, a, sig)
        self.assertEqual(y, y_recovered)
