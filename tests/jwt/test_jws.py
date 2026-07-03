# SPDX-FileCopyrightText: Copyright 2025 Siemens AG
# SPDX-License-Identifier: Apache-2.0
#
# The original code is from the cmp-test-suite project:
#   https://github.com/siemens/cmp-test-suite
#  Code owner: Alexandr Railean
# This code may be modified, or just copy pasted from the original.
#

"""Sign/verify tests for the compact JWS (JWT) layer.

Covers round-trips for every supported key family, header shape, algorithm
allowlisting, the security rejections (``alg:"none"``, non-signing keys,
tamper, wrong key), and external interop against RFC known-answer tokens.
"""

import json
import unittest

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed448, ed25519, rsa, x25519
from cryptography.hazmat.primitives.asymmetric import padding as rsa_padding
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

from keyutils_py import generate_key, sign_jwt, verify_jwt
from keyutils_py.exceptions import InvalidJWS
from keyutils_py.jwt import key_from_jwk, sign_jws, verify_jws
from keyutils_py.jwt.jwt_utils import b64u_decode

CLAIMS = {"iss": "keyutils-py", "sub": "alice", "scope": ["read", "write"]}


def _header(token):
    return json.loads(b64u_decode(token.split(".")[0]))


class TestRoundTrip(unittest.TestCase):
    """sign_jwt -> verify_jwt returns the claims for every family."""

    def _assert_roundtrip(self, key, expected_alg, **sign_kwargs):
        token = sign_jwt(CLAIMS, key, **sign_kwargs)
        self.assertEqual(len(token.split(".")), 3)
        header = _header(token)
        self.assertEqual(header["alg"], expected_alg)
        self.assertEqual(header["typ"], "JWT")
        self.assertEqual(verify_jwt(token, key), CLAIMS)
        # A public key verifies just as well as the private key.
        self.assertEqual(verify_jwt(token, key.public_key()), CLAIMS)

    def test_rsa_default_rs256(self):
        self._assert_roundtrip(rsa.generate_private_key(public_exponent=65537, key_size=2048), "RS256")

    def test_rsa_overrides(self):
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        for alg in ("RS384", "RS512", "PS256", "PS384", "PS512"):
            with self.subTest(alg=alg):
                self._assert_roundtrip(key, alg, alg=alg)

    def test_ec_curves(self):
        for curve, alg in (
            (ec.SECP256R1(), "ES256"),
            (ec.SECP384R1(), "ES384"),
            (ec.SECP521R1(), "ES512"),
            (ec.SECP256K1(), "ES256K"),
        ):
            with self.subTest(alg=alg):
                self._assert_roundtrip(ec.generate_private_key(curve), alg)

    def test_eddsa(self):
        self._assert_roundtrip(ed25519.Ed25519PrivateKey.generate(), "EdDSA")
        self._assert_roundtrip(ed448.Ed448PrivateKey.generate(), "EdDSA")

    def test_ml_dsa(self):
        for alg in ("ml-dsa-44", "ml-dsa-65", "ml-dsa-87"):
            with self.subTest(alg=alg):
                self._assert_roundtrip(generate_key(alg), alg.upper())

    def test_slh_dsa(self):
        self._assert_roundtrip(generate_key("slh-dsa-sha2-128s"), "SLH-DSA-SHA2-128s")

    def test_composite(self):
        for name, alg in (
            ("composite-sig-ml-dsa-44-ed25519", "ML-DSA-44-Ed25519"),
            ("composite-sig-ml-dsa-44-ecdsa-secp256r1", "ML-DSA-44-ECDSA-P256"),
            ("composite-sig-ml-dsa-44-rsa2048", "ML-DSA-44-RSA2048"),
            ("composite-sig-ml-dsa-87-ed448", "ML-DSA-87-Ed448"),
        ):
            with self.subTest(alg=alg):
                self._assert_roundtrip(generate_key(name), alg)


class TestRawJws(unittest.TestCase):
    def test_bytes_payload_roundtrip(self):
        """sign_jws over arbitrary bytes returns them verbatim on verify_jws."""
        key = ed25519.Ed25519PrivateKey.generate()
        payload = b"\x00\x01 arbitrary bytes \xff"
        token = sign_jws(payload, key)
        header, recovered = verify_jws(token, key)
        self.assertEqual(recovered, payload)
        self.assertEqual(header["alg"], "EdDSA")
        self.assertNotIn("typ", header)


class TestStandardEncoding(unittest.TestCase):
    """Prove the emitted signatures are standard JOSE (verifiable by cryptography)."""

    def test_es256_is_raw_r_s(self):
        key = ec.generate_private_key(ec.SECP256R1())
        token = sign_jwt(CLAIMS, key, alg="ES256")
        h, p, s = token.split(".")
        sig = b64u_decode(s)
        self.assertEqual(len(sig), 64)  # raw R||S, not DER
        r = int.from_bytes(sig[:32], "big")
        s_int = int.from_bytes(sig[32:], "big")
        # Independent verification via cryptography with the R||S->DER decoding.
        key.public_key().verify(
            encode_dss_signature(r, s_int), f"{h}.{p}".encode("ascii"), ec.ECDSA(hashes.SHA256())
        )

    def test_rs256_is_standard(self):
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        token = sign_jwt(CLAIMS, key)
        h, p, s = token.split(".")
        key.public_key().verify(
            b64u_decode(s), f"{h}.{p}".encode("ascii"), rsa_padding.PKCS1v15(), hashes.SHA256()
        )


class TestExternalInterop(unittest.TestCase):
    """Verify tokens produced by an external implementation (the RFCs)."""

    def test_rfc8037_eddsa(self):
        """RFC 8037 Appendix A.4 Ed25519 JWS verifies with the Appendix A.1 key."""
        jwk = {
            "kty": "OKP",
            "crv": "Ed25519",
            "d": "nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A",
            "x": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo",
        }
        token = (
            "eyJhbGciOiJFZERTQSJ9."
            "RXhhbXBsZSBvZiBFZDI1NTE5IHNpZ25pbmc."
            "hgyY0il_MGCjP0JzlnLWG1PPOt7-09PGcvMg3AIbQR6dWbhijcNR4ki4iylGjg5"
            "BhVsPt9g7sVvpAr_MuM0KAg"
        )
        header, payload = verify_jws(token, key_from_jwk(jwk))
        self.assertEqual(header["alg"], "EdDSA")
        self.assertEqual(payload, b"Example of Ed25519 signing")

    def test_rfc8037_eddsa_tamper_rejected(self):
        jwk = {"kty": "OKP", "crv": "Ed25519", "x": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}
        token = (
            "eyJhbGciOiJFZERTQSJ9."
            "RXhhbXBsZSBvZiBFZDI1NTE5IHNpZ25pbmd."  # payload altered
            "hgyY0il_MGCjP0JzlnLWG1PPOt7-09PGcvMg3AIbQR6dWbhijcNR4ki4iylGjg5"
            "BhVsPt9g7sVvpAr_MuM0KAg"
        )
        with self.assertRaises(InvalidJWS):
            verify_jws(token, key_from_jwk(jwk))


class TestSecurity(unittest.TestCase):
    def test_tampered_signature_rejected(self):
        key = ec.generate_private_key(ec.SECP256R1())
        token = sign_jwt(CLAIMS, key)
        h, p, s = token.split(".")
        forged = f"{h}.{p}.{('A' * len(s)) if s[0] != 'A' else ('B' * len(s))}"
        with self.assertRaises(InvalidJWS):
            verify_jwt(forged, key)

    def test_tampered_payload_rejected(self):
        key = ed25519.Ed25519PrivateKey.generate()
        h, p, s = sign_jwt(CLAIMS, key).split(".")
        from keyutils_py.jwt.jwt_utils import b64u_encode

        forged = f"{h}.{b64u_encode(json.dumps({'iss': 'attacker'}).encode())}.{s}"
        with self.assertRaises(InvalidJWS):
            verify_jwt(forged, key)

    def test_wrong_key_rejected(self):
        token = sign_jwt(CLAIMS, generate_key("ml-dsa-44"))
        with self.assertRaises(InvalidJWS):
            verify_jwt(token, generate_key("ml-dsa-44"))

    def test_alg_none_rejected(self):
        from keyutils_py.jwt.jwt_utils import b64u_encode

        header = b64u_encode(json.dumps({"alg": "none"}).encode())
        payload = b64u_encode(json.dumps(CLAIMS).encode())
        with self.assertRaises(InvalidJWS):
            verify_jwt(f"{header}.{payload}.", ec.generate_private_key(ec.SECP256R1()))

    def test_algorithms_allowlist_enforced(self):
        key = ec.generate_private_key(ec.SECP256R1())
        token = sign_jwt(CLAIMS, key)
        self.assertEqual(verify_jwt(token, key, algorithms=["ES256"]), CLAIMS)
        with self.assertRaises(InvalidJWS):
            verify_jwt(token, key, algorithms=["RS256", "ES384"])

    def test_alg_key_mismatch_rejected(self):
        """A token claiming an alg the key cannot produce is rejected (alg confusion)."""
        rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        ec_key = ec.generate_private_key(ec.SECP256R1())
        token = sign_jwt(CLAIMS, rsa_key)  # RS256
        with self.assertRaises(InvalidJWS):
            verify_jwt(token, ec_key)  # EC key only permits ES256

    def test_non_signing_keys_rejected(self):
        for key in (generate_key("ml-kem-768"), x25519.X25519PrivateKey.generate()):
            with self.subTest(key=type(key).__name__), self.assertRaises(InvalidJWS):
                sign_jwt(CLAIMS, key)

    def test_explicit_alg_incompatible_with_key(self):
        key = ec.generate_private_key(ec.SECP256R1())
        with self.assertRaises(InvalidJWS):
            sign_jwt(CLAIMS, key, alg="ES384")

    def test_malformed_token_rejected(self):
        key = ec.generate_private_key(ec.SECP256R1())
        for bad in ("only.two", "a.b.c.d", "not-a-token"):
            with self.subTest(token=bad), self.assertRaises(InvalidJWS):
                verify_jwt(bad, key)


if __name__ == "__main__":
    unittest.main()
