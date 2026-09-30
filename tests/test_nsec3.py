"""NSEC3 原语测试：RFC 5155 附录 A 官方向量 + Base32hex/线型编码边界。

哈希向量已经通过独立的 openssl 命令行迭代链路交叉复核，不依赖被测实现。
"""

import hashlib
import unittest

from app.nsec3 import (
    B32HEX_ALPHABET,
    Base32HexError,
    NameError,
    decode_base32hex,
    encode_base32hex,
    nsec3_hash,
    nsec3_hash_raw,
    to_wire,
)

RFC_SALT = bytes.fromhex("aabbccdd")
RFC_ITERS = 12

# RFC 5155 Appendix A（salt=aabbccdd，12 轮），经 openssl 独立链路复核
RFC_VECTORS = {
    "example": "0P9MHAVEQVM6T7VBL5LOP2U3T2RP3TOM",
    "alfa.example": "217ULFRBRP2HTR1EELB9JQ39EEA5G9UC",
    "ns1.example": "2T7B4G4VSA5SMI47K61MV5BV1A22BOJR",
    "ns2.example": "Q04JKCEVQVMU85R014C7DKBA38O0JI5R",
    "w.example": "K8UDEMVP1J2F7EG6JEBPS17VP3N8I58H",
    "x.example": "B76EQLMTQ7S6IULHLPOQGM1COPU2PCA6",
    "c.example": "4G6P9U5GVFSHP30PQECJ98B3MAQBN1CK",
    "*.example": "JHSV97RODSNHC4F1KE4JH23EGAA5AGVP",
    "a.c.example": "U5KHQI4917VS9CA7IRC0TOT78AM6208L",
    "x.w.c.example": "H7H8J87CVPS0LJ5Q5PU6L41B4KGCLJFF",
    "x.y.w.example": "2VPTU5TIMAMQTTGL4LUU9KG21E0AOR3S",
    "2t7b4g4vsa5smi47k61mv5bv1a22bojr.example":
        "KOHAR7MBB8DC2CE8A9QVL8HON4K53UHI",
}


class Rfc5155VectorsTest(unittest.TestCase):
    def test_vectors(self) -> None:
        for name, expected in RFC_VECTORS.items():
            with self.subTest(name=name):
                got = nsec3_hash(
                    name, RFC_SALT, RFC_ITERS, allow_wildcard=name.startswith("*")
                )
                self.assertEqual(got, expected)

    def test_iterations_zero_empty_salt(self) -> None:
        expect = encode_base32hex(hashlib.sha1(to_wire("example")).digest())
        self.assertEqual(nsec3_hash("example", b"", 0), expect)

    def test_case_insensitive_names(self) -> None:
        self.assertEqual(
            nsec3_hash("NS1.Example", RFC_SALT, RFC_ITERS),
            nsec3_hash("ns1.example", RFC_SALT, RFC_ITERS),
        )
        self.assertEqual(
            nsec3_hash("ns1.example.", RFC_SALT, RFC_ITERS),
            nsec3_hash("ns1.example", RFC_SALT, RFC_ITERS),
        )

    def test_wildcard_wire_encoding(self) -> None:
        self.assertEqual(
            to_wire("*.example", allow_wildcard=True), b"\x01*\x07example\x00"
        )
        with self.assertRaises(NameError):
            to_wire("*.example")  # 默认不接受通配符标签


class Base32HexTest(unittest.TestCase):
    def test_roundtrip_all_lengths(self) -> None:
        for n in range(1, 41):
            data = bytes((i * 37 + n) & 0xFF for i in range(n))
            self.assertEqual(decode_base32hex(encode_base32hex(data)), data)

    def test_alphabet_constant(self) -> None:
        self.assertEqual(B32HEX_ALPHABET, "0123456789ABCDEFGHIJKLMNOPQRSTUV")

    def test_illegal_chars_and_padding(self) -> None:
        with self.assertRaises(Base32HexError):
            decode_base32hex("W" * 32)          # W-Z 不属于 base32hex
        with self.assertRaises(Base32HexError):
            decode_base32hex("0" * 31 + "=")    # 不允许填充
        with self.assertRaises(Base32HexError):
            decode_base32hex(" 0000000000000000000000000000000")  # 空白
        with self.assertRaises(Base32HexError):
            decode_base32hex("")

    def test_trailing_bits_must_be_zero(self) -> None:
        # 31 个全 1 字符 = 155 位 → 19 字节 + 3 个非零尾部位
        with self.assertRaises(Base32HexError):
            decode_base32hex("V" * 31)

    def test_sha1_hash_text_length(self) -> None:
        text = nsec3_hash("example", RFC_SALT, RFC_ITERS)
        self.assertEqual(len(text), 32)
        self.assertEqual(len(decode_base32hex(text)), 20)


class RawDigestTest(unittest.TestCase):
    def test_raw_is_20_bytes(self) -> None:
        self.assertEqual(len(nsec3_hash_raw("example", RFC_SALT, RFC_ITERS)), 20)

    def test_bad_iterations(self) -> None:
        with self.assertRaises(ValueError):
            nsec3_hash_raw("example", RFC_SALT, -1)
        with self.assertRaises(ValueError):
            nsec3_hash_raw("example", RFC_SALT, 65536)

    def test_bad_salt_type(self) -> None:
        with self.assertRaises(TypeError):
            nsec3_hash_raw("example", "aabbccdd", 0)  # type: ignore[arg-type]


if __name__ == "__main__":
    unittest.main()
