"""RFC 5155 NSEC3 原语：SHA-1 迭代哈希、Base32hex 编解码、线型名称处理。

本模块只实现算法原语，不含任何证明判定逻辑，便于审查员独立复算：

    H0    = SHA-1(wire(name) || salt)
    H(k)  = SHA-1(H(k-1)     || salt), 0 < k <= iterations
    输出  = Base32hex(H(K))，字母表 0-9A-V，无填充（RFC 4648 第 7 节）
"""

from __future__ import annotations

import hashlib

# RFC 4648 Section 7 的 base32hex 字母表（与常规 base32 字母表不同）
B32HEX_ALPHABET = "0123456789ABCDEFGHIJKLMNOPQRSTUV"
_B32HEX_DECODE = {ch: i for i, ch in enumerate(B32HEX_ALPHABET)}
_B32HEX_DECODE.update({ch.lower(): i for i, ch in enumerate(B32HEX_ALPHABET)})

SHA1_DIGEST_LEN = 20
# SHA-1 摘要的无填充 base32hex 长度恒为 32 个字符
SHA1_B32HEX_LEN = 32

MAX_LABEL_LEN = 63
MAX_NAME_WIRE_LEN = 255


class NameError(ValueError):
    """域名不符合 LDH 线型名称规则。"""


class Base32HexError(ValueError):
    """字符串不是合法的无填充 Base32hex。"""


def split_labels(name: str) -> list[str]:
    """把域名切成小写标签列表，去掉根标与末尾点。"""
    if not isinstance(name, str):
        raise NameError("域名必须是字符串")
    trimmed = name[:-1] if name.endswith(".") else name
    if trimmed.endswith("."):
        raise NameError("域名含多个末尾点")
    if not trimmed:
        raise NameError("域名不能为空")
    labels = trimmed.split(".")
    return [label.lower() for label in labels]


def validate_labels(labels: list[str], *, allow_wildcard: bool = False) -> None:
    wire_len = 1  # 根标
    for index, label in enumerate(labels):
        if allow_wildcard and index == 0 and label == "*":
            wire_len += 2
            continue
        if not (1 <= len(label) <= MAX_LABEL_LEN):
            raise NameError(f"标签长度非法: {label!r}")
        if label.startswith("-") or label.endswith("-"):
            raise NameError(f"标签不得以连字符开头或结尾: {label!r}")
        for ch in label:
            if not (ch.isascii() and (ch.isdigit() or ch.isalpha() or ch == "-")):
                raise NameError(f"标签含非 LDH 字符: {label!r}")
        wire_len += 1 + len(label)
    if wire_len > MAX_NAME_WIRE_LEN:
        raise NameError("域名线长超过 255 字节")


def canonical_name(name: str, *, allow_wildcard: bool = False) -> str:
    """归一化为不带末尾点的小写规范名称。"""
    labels = split_labels(name)
    validate_labels(labels, allow_wildcard=allow_wildcard)
    return ".".join(labels)


def to_wire(name: str, *, allow_wildcard: bool = False) -> bytes:
    """名称转 RFC 1035 线型编码（NSEC3 哈希输入 X）。"""
    labels = split_labels(name)
    validate_labels(labels, allow_wildcard=allow_wildcard)
    buf = bytearray()
    for i, label in enumerate(labels):
        if allow_wildcard and i == 0 and label == "*":
            buf.append(1)
            buf.append(0x2A)  # '*'
            continue
        encoded = label.encode("ascii")
        buf.append(len(encoded))
        buf.extend(encoded)
    buf.append(0)
    return bytes(buf)


def encode_base32hex(data: bytes) -> str:
    """RFC 4648 base32hex 无填充编码，输出大写。"""
    result = []
    # 按 5 位分组
    acc = 0
    bits = 0
    for byte in data:
        acc = (acc << 8) | byte
        bits += 8
        while bits >= 5:
            bits -= 5
            result.append(B32HEX_ALPHABET[(acc >> bits) & 0x1F])
    if bits:
        result.append(B32HEX_ALPHABET[(acc << (5 - bits)) & 0x1F])
    return "".join(result)


def decode_base32hex(text: str) -> bytes:
    """严格解码无填充 base32hex；拒绝填充、空白与非法字符。"""
    if not isinstance(text, str) or not text:
        raise Base32HexError("base32hex 字符串为空")
    if "=" in text or text != text.strip():
        raise Base32HexError("base32hex 不得含填充或空白")
    acc = 0
    bits = 0
    out = bytearray()
    for ch in text:
        value = _B32HEX_DECODE.get(ch)
        if value is None:
            raise Base32HexError(f"base32hex 含非法字符: {ch!r}")
        acc = (acc << 5) | value
        bits += 5
        if bits >= 8:
            bits -= 8
            out.append((acc >> bits) & 0xFF)
    # 合法的无填充编码末尾剩余位必须为 0
    if bits and (acc & ((1 << bits) - 1)):
        raise Base32HexError("base32hex 末尾剩余位非 0")
    return bytes(out)


def nsec3_hash_raw(
    name: str, salt: bytes, iterations: int, *, allow_wildcard: bool = False
) -> bytes:
    """计算 NSEC3 原始 20 字节摘要。"""
    if not isinstance(salt, (bytes, bytearray)):
        raise TypeError("salt 必须是字节串")
    if not isinstance(iterations, int) or not (0 <= iterations <= 0xFFFF):
        raise ValueError("迭代次数必须是 0..65535 的整数")
    digest = hashlib.sha1(
        to_wire(name, allow_wildcard=allow_wildcard) + bytes(salt)
    ).digest()
    for _ in range(iterations):
        digest = hashlib.sha1(digest + bytes(salt)).digest()
    return digest


def nsec3_hash(
    name: str, salt: bytes, iterations: int, *, allow_wildcard: bool = False
) -> str:
    """计算 NSEC3 哈希的大写无填充 Base32hex 文本。"""
    return encode_base32hex(
        nsec3_hash_raw(name, salt, iterations, allow_wildcard=allow_wildcard)
    )
