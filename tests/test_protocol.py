import unittest

from zyb_search_api.protocol import (
    accept_sign_b,
    create_sign_a,
    decode_wire,
    des_decrypt,
    des_encrypt,
    encode_wire,
    request_sign,
    response_key,
)


class ProtocolTests(unittest.TestCase):
    def test_native_des_vector(self):
        clear = b"8&%d*##BBBBBBBBBB##2fb53de6d38eff7109f19d68e047123b##E0DA888804E90201780A9C0D17D0B050|0"
        expected = (
            "8df33e23f867646595a8e3a2b3f019693b82fd90bbf6ae3afe1f6cd600bfe2bb"
            "e4fd5488b35c19972d4f312d7367b384d7a34d34ae655473c30df79f1e33d722"
            "b09d8caf31f2f36f4851aa296652fb7faf5a0a07884d8e70"
        )
        cipher = des_encrypt(clear, b"@fG2SuLA")
        self.assertEqual(cipher.hex(), expected)
        self.assertEqual(des_decrypt(decode_wire(encode_wire(cipher)), b"@fG2SuLA"), clear)

    def test_handshake_round_trip(self):
        cuid = "TEST-CUID|0"
        challenge = "ABCDE12345"
        token = "rsbV4048PW"
        sign_a, returned_challenge = create_sign_a(cuid, challenge)
        key = (challenge[:5] + "#G4").encode("ascii")
        sign_b = encode_wire(des_encrypt(f"{challenge}##{token}".encode(), key))
        self.assertEqual(returned_challenge, challenge)
        self.assertEqual(accept_sign_b(cuid, sign_a, sign_b), token)

    def test_native_sign_vector(self):
        self.assertEqual(
            request_sign("YWJj", "rsbV4048PW"),
            "12ca66351c37c5fe0e0314c7e4689d33",
        )

    def test_native_response_key_vector(self):
        self.assertEqual(
            response_key("2810", "rsbV4048PW"),
            "70d9aac75172a49edb6063a473c01bb16a55a8e808bc17c8ab697e8cc07341be"
            "fe888bff7cd3cab59f063880ae27736631cd22941af1d9898bc5ba70303e7918",
        )


if __name__ == "__main__":
    unittest.main()
