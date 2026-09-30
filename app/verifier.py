"""NSEC3 NXDOMAIN 不存在证明的离线审计判定（RFC 5155 + RFC 7129）。

本模块只做“最近存在祖先证明”（Closest Encloser Proof）的判定：

1. 最近存在祖先 CE ：目标名称的祖先链上，哈希等于某条 NSEC3 owner 的最深名称；
2. 下一层名称 NC ：CE 之下、通往目标名称路径上的第一层名称，必须被某条 NSEC3
   的环形半开区间 (owner, next] 覆盖（覆盖 ≠ 命中 owner）；
3. 通配符名称 WC ：``*.CE``，同样必须被某条 NSEC3 区间覆盖。

三项事实分别由记录组中的记录承担（同一条记录可承担多项），全部成立才允许
给出 NXDOMAIN 通过结论。仅接受 SHA-1（算法号 1）且 flags=0（无 Opt-Out）。
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from .nsec3 import (
    SHA1_B32HEX_LEN,
    Base32HexError,
    NameError,
    canonical_name,
    decode_base32hex,
    nsec3_hash,
    split_labels,
    validate_labels,
)

AUDIT_ID_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
HEX_RE = re.compile(r"^[0-9A-Fa-f]*$")

# 常见类型助记符 -> 类型号（审查只需展示与校验位图，无需覆盖全部）
TYPE_NUMBERS: dict[str, int] = {
    "A": 1,
    "NS": 2,
    "CNAME": 5,
    "SOA": 6,
    "PTR": 12,
    "HINFO": 13,
    "MX": 15,
    "TXT": 16,
    "AAAA": 28,
    "SRV": 33,
    "DS": 43,
    "RRSIG": 46,
    "NSEC": 47,
    "DNSKEY": 48,
    "NSEC3": 50,
    "NSEC3PARAM": 51,
    "SPF": 99,
    "CAA": 257,
}
NUMBER_TYPES = {v: k for k, v in TYPE_NUMBERS.items()}

# 事实标签
FACT_MATCH_CE = "MATCH_CLOSEST_ENCLOSER"
FACT_COVER_NC = "COVER_NEXT_CLOSER"
FACT_COVER_WC = "COVER_WILDCARD"


class VerificationFailure(Exception):
    """输入载荷在进入判定前就不合法（始终拒绝）。"""

    def __init__(self, code: str, message: str, record_index: int | None = None):
        super().__init__(message)
        self.code = code
        self.message = message
        self.record_index = record_index


@dataclass
class Record:
    index: int
    owner_hash: str          # 大写 base32hex 文本
    next_hash: str
    owner_hex: str           # 20 字节 -> 40 位十六进制
    next_hex: str
    types: list[str]
    algorithm: int = 1
    flags: int = 0

    @property
    def wraps(self) -> bool:
        """owner > next 表示该记录是环上跨零的最后一条。"""
        return int(self.owner_hex, 16) > int(self.next_hex, 16)

    @property
    def self_loop(self) -> bool:
        """owner == next：只有环上仅有一个 NSEC3 节点时合法。"""
        return self.owner_hex == self.next_hex

    def covers(self, hash_hex: str) -> bool:
        """半开环形区间 (owner, next] 是否覆盖该哈希。

        任何等于 owner 集合中某点的哈希都应先按“命中”处理，绝不能按覆盖
        处理；调用方负责先行检查命中。
        """
        x = int(hash_hex, 16)
        o = int(self.owner_hex, 16)
        n = int(self.next_hex, 16)
        if o == n:
            return x != o
        if o < n:
            return o < x <= n
        return x > o or x <= n

    def describe(self) -> dict[str, Any]:
        return {
            "index": self.index,
            "owner_hash": self.owner_hash,
            "next_hash": self.next_hash,
            "owner_hex": self.owner_hex,
            "next_hex": self.next_hex,
            "types": self.types,
            "wrap_direction": (
                "SELF_LOOP" if self.self_loop else ("WRAP_AROUND" if self.wraps else "FORWARD")
            ),
        }


@dataclass
class _Builder:
    failures: list[dict[str, Any]] = field(default_factory=list)

    def reject(self, code: str, message: str, record_index: int | None = None) -> None:
        self.failures.append({"code": code, "message": message, "record_index": record_index})


def _parse_type_bitmap(raw: Any, index: int) -> list[str]:
    if raw is None:
        return []
    if not isinstance(raw, list):
        raise VerificationFailure("BAD_TYPE_BITMAP", "类型位图必须是数组", index)
    seen: set[str] = set()
    out: list[str] = []
    for item in raw:
        if not isinstance(item, str) or not item.strip():
            raise VerificationFailure("BAD_TYPE_BITMAP", "类型位图条目必须是非空字符串", index)
        token = item.strip().upper()
        number: int | None = None
        if token in TYPE_NUMBERS:
            number = TYPE_NUMBERS[token]
            label = token
        elif token.startswith("TYPE") and token[4:].isdigit():
            number = int(token[4:])
            if not 0 <= number <= 0xFFFF:
                raise VerificationFailure("BAD_TYPE_BITMAP", f"类型号越界: {token}", index)
            label = NUMBER_TYPES.get(number, f"TYPE{number}")
        else:
            raise VerificationFailure("BAD_TYPE_BITMAP", f"未知类型助记符: {item}", index)
        key = f"TYPE{number}"
        if key in seen:
            raise VerificationFailure("BAD_TYPE_BITMAP", f"类型位图重复: {label}", index)
        seen.add(key)
        out.append(label)
    return out


def _parse_record(raw: Any, index: int) -> Record:
    if not isinstance(raw, dict):
        raise VerificationFailure("BAD_RECORD", "记录组中的每条记录必须是对象", index)
    owner = raw.get("owner_hash")
    nxt = raw.get("next_hash")
    if not isinstance(owner, str) or not isinstance(nxt, str):
        raise VerificationFailure("BAD_RECORD", "owner_hash / next_hash 必须是字符串", index)
    owner = owner.strip().upper()
    nxt = nxt.strip().upper()
    decoded: dict[str, bytes] = {}
    for field_name, text in (("owner_hash", owner), ("next_hash", nxt)):
        # 先验长度：截断/补齐伪造的 SHA-1 哈希长度必然不对
        if len(text) != SHA1_B32HEX_LEN:
            raise VerificationFailure(
                "TRUNCATED_HASH",
                f"{field_name} 长度 {len(text)} != {SHA1_B32HEX_LEN}，"
                "不是完整的 20 字节 SHA-1 哈希（疑似截断证据）",
                index,
            )
        try:
            raw_bytes = decode_base32hex(text)
        except Base32HexError as exc:
            raise VerificationFailure(
                "ILLEGAL_BASE32HEX", f"{field_name} 非法 Base32hex: {exc}", index
            ) from exc
        if len(raw_bytes) != 20:
            raise VerificationFailure(
                "TRUNCATED_HASH", f"{field_name} 不是 20 字节 SHA-1 哈希（疑似截断证据）", index
            )
        decoded[field_name] = raw_bytes
    algorithm = raw.get("algorithm", 1)
    flags = raw.get("flags", 0)
    if not isinstance(algorithm, int) or isinstance(algorithm, bool):
        raise VerificationFailure("BAD_RECORD", "algorithm 必须是整数", index)
    if not isinstance(flags, int) or isinstance(flags, bool):
        raise VerificationFailure("BAD_RECORD", "flags 必须是整数", index)
    if algorithm != 1:
        raise VerificationFailure(
            "UNSUPPORTED_ALGORITHM", "本服务仅处理 SHA-1（algorithm=1）NSEC3", index
        )
    if flags != 0:
        raise VerificationFailure(
            "OPT_OUT_UNSUPPORTED", "本服务不接受 Opt-Out（flags 必须为 0）的 NSEC3", index
        )
    types = _parse_type_bitmap(raw.get("types", []), index)
    return Record(
        index=index,
        owner_hash=owner,
        next_hash=nxt,
        owner_hex=raw_bytes_hex(owner),
        next_hex=raw_bytes_hex(nxt),
        types=types,
        algorithm=algorithm,
        flags=flags,
    )


def raw_bytes_hex(b32_text: str) -> str:
    return decode_base32hex(b32_text).hex()


def _parse_parameters(payload: dict[str, Any]) -> tuple[str, str, bytes, int]:
    audit_id = payload.get("audit_id")
    if not isinstance(audit_id, str) or not AUDIT_ID_RE.fullmatch(audit_id):
        raise VerificationFailure(
            "BAD_AUDIT_ID", "稳定审计标识须为 1-64 位字母/数字/下划线/连字符"
        )

    def _name(key: str, *, wildcard: bool = False) -> str:
        value = payload.get(key)
        if not isinstance(value, str) or not value.strip():
            raise VerificationFailure("BAD_NAME", f"{key} 不能为空")
        try:
            labels = split_labels(value)
            validate_labels(labels, allow_wildcard=wildcard)
        except NameError as exc:
            raise VerificationFailure("BAD_NAME", f"{key} 非法: {exc}") from exc
        return ".".join(labels)

    zone = _name("zone")
    qname = _name("qname")

    zlabels = zone.split(".")
    qlabels = qname.split(".")
    if len(qlabels) <= len(zlabels) or qlabels[-len(zlabels):] != zlabels:
        raise VerificationFailure(
            "OUT_OF_ZONE", f"目标名称 {qname} 不在区域 {zone} 之内（或等于区域顶点）"
        )

    salt_hex = payload.get("salt", "")
    if not isinstance(salt_hex, str) or not HEX_RE.fullmatch(salt_hex) or len(salt_hex) % 2:
        raise VerificationFailure("BAD_SALT", "盐值必须是偶数位十六进制字符串（允许为空）")
    salt = bytes.fromhex(salt_hex)
    if len(salt) > 255:
        raise VerificationFailure("BAD_SALT", "盐值长度超过 255 字节")

    iterations = payload.get("iterations")
    if not isinstance(iterations, int) or isinstance(iterations, bool):
        raise VerificationFailure("BAD_ITERATIONS", "迭代次数必须是整数")
    if not 0 <= iterations <= 0xFFFF:
        raise VerificationFailure("BAD_ITERATIONS", "迭代次数必须在 0..65535 之间")
    return audit_id, zone, salt, iterations


def _hash_b32(name: str, salt: bytes, iterations: int) -> str:
    """计算名称哈希；首标签为 ``*`` 时按线型通配符名称编码。"""
    wildcard = name.split(".", 1)[0] == "*"
    return nsec3_hash(name, salt, iterations, allow_wildcard=wildcard)


def _interval_evidence(rec: Record, hash_hex: str) -> dict[str, Any]:
    x = int(hash_hex, 16)
    o = int(rec.owner_hex, 16)
    n = int(rec.next_hex, 16)
    return {
        "record_index": rec.index,
        "record": rec.describe(),
        "wrap_direction": rec.describe()["wrap_direction"],
        "ordering": {
            "owner_160": str(o),
            "hash_160": str(x),
            "next_160": str(n),
            "half_open_interval": "(owner, next] on ring mod 2^160",
        },
    }


def _ancestor_names(zone: str, qname: str) -> list[str]:
    zlabels = zone.split(".")
    qlabels = qname.split(".")
    names: list[str] = []
    for cut in range(len(zlabels), len(qlabels) + 1):
        names.append(".".join(qlabels[-cut:]))
    return names  # 顶点 -> 目标，按深度递增


def audit(payload: dict[str, Any]) -> dict[str, Any]:
    """对一次提交执行全部审计，返回可冻结、可复算的结论。"""
    b = _Builder()

    audit_id, zone, salt, iterations = _parse_parameters(payload)
    qname = canonical_name(payload["qname"])

    raw_records = payload.get("records")
    if not isinstance(raw_records, list) or not raw_records:
        raise VerificationFailure("NO_RECORDS", "记录组不能为空")

    records: list[Record] = []
    # 记录级解析错误：任意一条非法都不得给出通过结论
    for i, raw in enumerate(raw_records):
        records.append(_parse_record(raw, i))

    # 重复 owner：同一 owner 出现两条记录即证据冲突
    owners = [r.owner_hex for r in records]
    if len(set(owners)) != len(owners):
        dup = sorted({h for h in owners if owners.count(h) > 1})
        b.reject(
            "DUPLICATE_OWNER",
            f"记录组出现重复 owner 哈希: {', '.join(dup)}",
        )

    # 链一致性：即使只提交部分相关记录（真实响应如此），真实 NSEC3 链的
    # 每条边 (owner, next] 内部也不可能存在另一个真实 owner——next 本就是
    # owner 的直接后继。若提交的另一条记录 owner 落在区间内部（不等于
    # next 端点），则区间重叠/错误环绕，记录组自相矛盾。
    self_loops = [r for r in records if r.self_loop]
    if self_loops and len(records) > 1:
        r = self_loops[0]
        b.reject(
            "ASSERTION_CONFLICT",
            "owner == next 的自环记录声称环上只有一个名称，却同时提交了其他记录",
            r.index,
        )
    else:
        for r in records:
            for s in records:
                if r.index == s.index:
                    continue
                if r.covers(s.owner_hex) and s.owner_hex != r.next_hex:
                    b.reject(
                        "ASSERTION_CONFLICT",
                        f"记录 {r.index} 的区间 (owner, next] 内部包含记录 {s.index} 的 owner，"
                        "与 NSEC3 链边的不相交性矛盾（错误环绕区间或伪造记录）",
                        r.index,
                    )

    owner_set = set(owners)
    by_owner = {r.owner_hex: r for r in records}

    # 逐祖先精确计算迭代哈希
    ancestor_rows: list[dict[str, Any]] = []
    names = _ancestor_names(zone, qname)
    name_hash_hex: dict[str, str] = {}
    for name in names:
        h = _hash_b32(name, salt, iterations)
        name_hash_hex[name] = raw_bytes_hex(h)
        ancestor_rows.append(
            {"name": name, "hash_b32hex": h, "hash_hex": name_hash_hex[name], "role": "ANCESTOR"}
        )

    # CE：最深的、哈希命中 owner 的祖先
    ce_name: str | None = None
    ce_record: Record | None = None
    for name in reversed(names):
        rec = by_owner.get(name_hash_hex[name])
        if rec is not None:
            ce_name = name
            ce_record = rec
            break

    ce_evidence: dict[str, Any] | None = None
    nc_evidence: dict[str, Any] | None = None
    wc_evidence: dict[str, Any] | None = None

    if ce_name is None:
        b.reject(
            "INSUFFICIENT_EVIDENCE",
            "祖先链上没有任何名称的哈希命中记录 owner，无法确定最近存在祖先",
        )
    else:
        for row in ancestor_rows:
            if row["name"] == ce_name:
                row["role"] = "CLOSEST_ENCLOSER"
            elif row["name"] == qname and ce_name == qname:
                row["role"] = "TARGET_EXISTS"
        assert ce_record is not None
        ce_evidence = {
            "name": ce_name,
            "hash_b32hex": _hash_b32(ce_name, salt, iterations),
            "matched_record_index": ce_record.index,
            "matched_record": ce_record.describe(),
        }

        if ce_name == qname:
            b.reject(
                "TARGET_NAME_EXISTS",
                "目标名称自身哈希命中 NSEC3 owner，名称存在，不能得出 NXDOMAIN",
            )
        else:
            ce_depth = names.index(ce_name)
            nc_name = names[ce_depth + 1]
            wc_name = "*." + ce_name
            nc_hash = name_hash_hex[nc_name]
            wc_hash_b32 = _hash_b32(wc_name, salt, iterations)
            wc_hash = raw_bytes_hex(wc_hash_b32)

            for row in ancestor_rows:
                if row["name"] == nc_name:
                    row["role"] = "NEXT_CLOSER"

            def _cover_fact(
                label_name: str, label_hash: str, miss_code: str, miss_msg: str
            ) -> dict[str, Any] | None:
                # 命中优先：哈希等于任何 owner 都绝不可以被“覆盖”
                if label_hash in owner_set:
                    b.reject(
                        "ASSERTION_CONFLICT",
                        f"{label_name} 的哈希命中了某条 NSEC3 owner，"
                        "不能同时被区间覆盖（断言冲突，该名称或通配符实际存在）",
                        by_owner[label_hash].index,
                    )
                    return None
                covering = next((r for r in records if r.covers(label_hash)), None)
                if covering is None:
                    b.reject(miss_code, miss_msg)
                    return {
                        "name": label_name,
                        "hash_b32hex": _hash_b32(label_name, salt, iterations),
                        "covered_by": None,
                    }
                return {
                    "name": label_name,
                    "hash_b32hex": _hash_b32(label_name, salt, iterations),
                    "covered_by": _interval_evidence(covering, label_hash),
                }

            nc_evidence = _cover_fact(
                nc_name,
                nc_hash,
                "MISSING_NEXT_CLOSER_COVER",
                "没有任何记录的半开哈希区间覆盖下一层名称（证据不足）",
            )
            wc_evidence = _cover_fact(
                wc_name,
                wc_hash,
                "MISSING_WILDCARD_COVER",
                "没有任何记录的半开哈希区间覆盖通配符 *.CE（遗漏通配符排除证据）",
            )

    # 汇总所用记录（去重，保持提交顺序）
    used_indices: list[int] = []
    facts_by_index: dict[int, list[str]] = {}

    def _mark(rec: Record | None, fact: str) -> None:
        if rec is None:
            return
        if rec.index not in facts_by_index:
            facts_by_index[rec.index] = []
            used_indices.append(rec.index)
        facts_by_index[rec.index].append(fact)

    if ce_record is not None:
        _mark(ce_record, FACT_MATCH_CE)
    for ev, fact in ((nc_evidence, FACT_COVER_NC), (wc_evidence, FACT_COVER_WC)):
        if ev and ev.get("covered_by"):
            _mark(records[ev["covered_by"]["record_index"]], fact)

    records_used = []
    for idx in used_indices:
        desc = records[idx].describe()
        desc["facts"] = facts_by_index[idx]
        records_used.append(desc)

    all_records = [r.describe() for r in records]

    passed = not b.failures
    result = {
        "audit_id": audit_id,
        "status": "PASS" if passed else "REJECTED",
        "passed": passed,
        "conclusion": (
            "NXDOMAIN_PROVEN" if passed else "NXDOMAIN_NOT_PROVEN"
        ),
        "rejection_reasons": b.failures,
        "parameters": {
            "zone": zone,
            "qname": qname,
            "salt_hex": salt.hex(),
            "iterations": iterations,
            "hash_algorithm": "SHA-1",
            "opt_out": False,
        },
        "evidence": {
            "closest_encloser": ce_evidence,
            "next_closer": nc_evidence,
            "wildcard": wc_evidence,
            "ancestors": ancestor_rows,
            "records_used": records_used,
            "all_records": all_records,
            "ring_semantics": {
                "interval": "(owner, next] half-open over 0..2^160-1",
                "match_before_cover": True,
                "forward": "owner < hash <= next",
                "wrap_around": "hash > owner 或 hash <= next（跨零环绕）",
            },
        },
    }
    return result


def normalized_payload(payload: dict[str, Any]) -> str:
    """把提交归一化后序列化，用于审计标识复用但载荷改变的检测。"""
    import json

    audit_id, zone, salt, iterations = _parse_parameters(payload)
    qname = canonical_name(payload["qname"])
    records = []
    for i, raw in enumerate(payload.get("records", [])):
        rec = _parse_record(raw, i)
        records.append(
            {
                "owner_hash": rec.owner_hash,
                "next_hash": rec.next_hash,
                "types": sorted(rec.types),
                "algorithm": rec.algorithm,
                "flags": rec.flags,
            }
        )
    # 记录顺序无 DNS 语义：按 owner（再按 next）排序归一化
    records.sort(key=lambda r: (r["owner_hash"], r["next_hash"]))
    canonical = {
        "zone": zone,
        "qname": qname,
        "salt_hex": salt.hex(),
        "iterations": iterations,
        "records": records,
    }
    return json.dumps(canonical, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
