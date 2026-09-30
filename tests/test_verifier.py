"""审计判定测试：RFC 5155 附录 I.5 官方证明 + 全部拒绝类别。"""

import copy
import unittest

from app.verifier import (
    FACT_COVER_NC,
    FACT_COVER_WC,
    FACT_MATCH_CE,
    VerificationFailure,
    audit,
)

# RFC 5155 Appendix I.5：qname=x.w.c.example 的 NXDOMAIN 最近存在祖先证明。
# 盐 aabbccdd，12 轮迭代；两条 NSEC3 分别承担 CE匹配+通配符覆盖、下一层覆盖。
RFC_RECORDS = [
    {  # owner=H(c.example) -> next=H(x.example)
        "owner_hash": "4G6P9U5GVFSHP30PQECJ98B3MAQBN1CK",
        "next_hash": "B76EQLMTQ7S6IULHLPOQGM1COPU2PCA6",
        "types": ["NS", "DS", "RRSIG"],
    },
    {  # owner=H(a.c.example) -> next=H(example)，跨零环绕
        "owner_hash": "U5KHQI4917VS9CA7IRC0TOT78AM6208L",
        "next_hash": "0P9MHAVEQVM6T7VBL5LOP2U3T2RP3TOM",
        "types": ["RRSIG"],
    },
]
RFC_PAYLOAD = {
    "audit_id": "RFC5155-I5",
    "zone": "example",
    "qname": "x.w.c.example",
    "salt": "aabbccdd",
    "iterations": 12,
    "records": RFC_RECORDS,
}


def codes(result) -> list[str]:
    return [x["code"] for x in result["rejection_reasons"]]


class RfcProofTest(unittest.TestCase):
    def test_official_appendix_i5_passes(self) -> None:
        r = audit(copy.deepcopy(RFC_PAYLOAD))
        self.assertTrue(r["passed"])
        self.assertEqual(r["status"], "PASS")
        self.assertEqual(r["conclusion"], "NXDOMAIN_PROVEN")
        ev = r["evidence"]
        self.assertEqual(ev["closest_encloser"]["name"], "c.example")
        self.assertEqual(ev["next_closer"]["name"], "w.c.example")
        self.assertEqual(ev["wildcard"]["name"], "*.c.example")
        # NC 由环绕区间覆盖，WC 由正向区间覆盖（RFC I.5 结构）
        self.assertEqual(
            ev["next_closer"]["covered_by"]["wrap_direction"], "WRAP_AROUND"
        )
        self.assertEqual(
            ev["wildcard"]["covered_by"]["wrap_direction"], "FORWARD"
        )
        facts = {u["index"]: u["facts"] for u in ev["records_used"]}
        self.assertEqual(facts[0], [FACT_MATCH_CE, FACT_COVER_WC])
        self.assertEqual(facts[1], [FACT_COVER_NC])

    def test_hash_values_independently_listed(self) -> None:
        r = audit(copy.deepcopy(RFC_PAYLOAD))
        ancestors = {x["name"]: x["hash_b32hex"] for x in r["evidence"]["ancestors"]}
        self.assertEqual(ancestors["c.example"], "4G6P9U5GVFSHP30PQECJ98B3MAQBN1CK")
        self.assertEqual(ancestors["w.c.example"], "VHK9B462QGN0P23F0RT8I8G78634QA7N")
        self.assertEqual(r["evidence"]["wildcard"]["hash_b32hex"],
                         "7QGUIHO2N908LOODRTA97KEPH0AAVA94")

    def test_reordered_records_still_pass(self) -> None:
        p = copy.deepcopy(RFC_PAYLOAD)
        p["records"] = list(reversed(p["records"]))
        p["audit_id"] = "RFC5155-I5-REORDER"
        self.assertTrue(audit(p)["passed"])


class RejectionTest(unittest.TestCase):
    def test_missing_next_closer_cover(self) -> None:
        p = copy.deepcopy(RFC_PAYLOAD)
        p["audit_id"] = "MISS-NC"
        p["records"] = [RFC_RECORDS[0]]  # 只保留 CE+WC 那条，环绕边缺失
        r = audit(p)
        self.assertFalse(r["passed"])
        self.assertIn("MISSING_NEXT_CLOSER_COVER", codes(r))

    def test_missing_wildcard_cover(self) -> None:
        p = copy.deepcopy(RFC_PAYLOAD)
        p["audit_id"] = "MISS-WC"
        p["records"] = [RFC_RECORDS[1]] + [
            {  # CE 匹配保留，但区间终点停在通配符哈希之前（5.. < 7QGU..）
                "owner_hash": "4G6P9U5GVFSHP30PQECJ98B3MAQBN1CK",
                "next_hash": "5" + "0" * 31,
                "types": ["NS"],
            }
        ]
        r = audit(p)
        self.assertIn("MISSING_WILDCARD_COVER", codes(r))
        self.assertFalse(r["passed"])

    def test_tampered_interval_truncates_wildcard(self) -> None:
        p = copy.deepcopy(RFC_PAYLOAD)
        p["audit_id"] = "TAMPER"
        p["records"] = copy.deepcopy(RFC_RECORDS)
        p["records"][0]["next_hash"] = "4G6P9U5GVFSHP30PQECJ98B3MAQBN1CL"
        r = audit(p)
        self.assertIn("MISSING_WILDCARD_COVER", codes(r))

    def test_illegal_base32hex_raises(self) -> None:
        p = copy.deepcopy(RFC_PAYLOAD)
        p["records"] = copy.deepcopy(RFC_RECORDS)
        p["records"][0]["next_hash"] = "W" * 32
        with self.assertRaises(VerificationFailure) as ctx:
            audit(p)
        self.assertEqual(ctx.exception.code, "ILLEGAL_BASE32HEX")

    def test_truncated_hash_raises(self) -> None:
        p = copy.deepcopy(RFC_PAYLOAD)
        p["records"] = copy.deepcopy(RFC_RECORDS)
        p["records"][1]["owner_hash"] = "U5KHQI49"
        with self.assertRaises(VerificationFailure) as ctx:
            audit(p)
        self.assertEqual(ctx.exception.code, "TRUNCATED_HASH")

    def test_duplicate_owner_rejected(self) -> None:
        p = copy.deepcopy(RFC_PAYLOAD)
        p["records"] = copy.deepcopy(RFC_RECORDS)
        p["records"].append(copy.deepcopy(RFC_RECORDS[0]))
        self.assertIn("DUPLICATE_OWNER", codes(audit(p)))

    def test_unsupported_algorithm_and_optout(self) -> None:
        for field_name, bad, expected in [
            ("algorithm", 2, "UNSUPPORTED_ALGORITHM"),
            ("flags", 1, "OPT_OUT_UNSUPPORTED"),
        ]:
            p = copy.deepcopy(RFC_PAYLOAD)
            p["records"] = copy.deepcopy(RFC_RECORDS)
            p["records"][0][field_name] = bad
            with self.subTest(field=field_name):
                with self.assertRaises(VerificationFailure) as ctx:
                    audit(p)
                self.assertEqual(ctx.exception.code, expected)

    def test_chain_edge_must_not_contain_other_owner(self) -> None:
        # 伪造记录：顶点 0P9M 的边直达 U5KHQ，区间内部严格包含真实 owner
        # 4G6P9U（c.example，本次的 CE），与 NSEC3 链边的不相交性矛盾。
        p = copy.deepcopy(RFC_PAYLOAD)
        p["records"] = [
            {"owner_hash": "0P9MHAVEQVM6T7VBL5LOP2U3T2RP3TOM",
             "next_hash": "U5KHQI4917VS9CA7IRC0TOT78AM6208L", "types": ["SOA"]},
            RFC_RECORDS[0],
        ]
        r = audit(p)
        self.assertIn("ASSERTION_CONFLICT", codes(r))

    def test_two_node_ring_pointing_each_other_is_consistent(self) -> None:
        # 两节点互指本身不构成链冲突（但对本 qname 证据不足）
        p = copy.deepcopy(RFC_PAYLOAD)
        p["records"] = [
            {"owner_hash": "4G6P9U5GVFSHP30PQECJ98B3MAQBN1CK",
             "next_hash": "U5KHQI4917VS9CA7IRC0TOT78AM6208L", "types": ["NS"]},
            {"owner_hash": "U5KHQI4917VS9CA7IRC0TOT78AM6208L",
             "next_hash": "4G6P9U5GVFSHP30PQECJ98B3MAQBN1CK", "types": ["RRSIG"]},
        ]
        self.assertNotIn("ASSERTION_CONFLICT", codes(audit(p)))

    def test_target_name_itself_exists(self) -> None:
        p = copy.deepcopy(RFC_PAYLOAD)
        p["qname"] = "c.example"  # 自身命中 owner
        self.assertIn("TARGET_NAME_EXISTS", codes(audit(p)))

    def test_next_closer_hash_equal_to_owner_is_conflict(self) -> None:
        # NC 哈希恰好等于某条 owner（下一层实际存在）：命中优先，不得按覆盖处理
        p = copy.deepcopy(RFC_PAYLOAD)
        p["records"] = [
            {"owner_hash": "4G6P9U5GVFSHP30PQECJ98B3MAQBN1CK",
             "next_hash": "VHK9B462QGN0P23F0RT8I8G78634QA7N", "types": ["NS"]},
            {"owner_hash": "VHK9B462QGN0P23F0RT8I8G78634QA7N",
             "next_hash": "B76EQLMTQ7S6IULHLPOQGM1COPU2PCA6", "types": ["A"]},
            RFC_RECORDS[1],
        ]
        r = audit(p)
        self.assertTrue(any(c in codes(r) for c in
                            ("ASSERTION_CONFLICT", "MISSING_NEXT_CLOSER_COVER")))


class ParameterTest(unittest.TestCase):
    def test_bad_parameters_raise(self) -> None:
        cases = [
            ({"audit_id": "bad id!"}, "BAD_AUDIT_ID"),
            ({"salt": "zz"}, "BAD_SALT"),
            ({"salt": "a"}, "BAD_SALT"),
            ({"iterations": 70000}, "BAD_ITERATIONS"),
            ({"iterations": "12"}, "BAD_ITERATIONS"),
            ({"qname": "x.w.c.other"}, "OUT_OF_ZONE"),
            ({"zone": "example", "qname": "example"}, "OUT_OF_ZONE"),
            ({"records": []}, "NO_RECORDS"),
        ]
        for mutate, expected in cases:
            p = copy.deepcopy(RFC_PAYLOAD)
            p.update(mutate)
            with self.subTest(case=expected):
                with self.assertRaises(VerificationFailure) as ctx:
                    audit(p)
                self.assertEqual(ctx.exception.code, expected)

    def test_only_sha1_optout_false_accepted(self) -> None:
        p = copy.deepcopy(RFC_PAYLOAD)
        # 显式给出合法 algorithm=1 / flags=0 也通过
        p["records"] = copy.deepcopy(RFC_RECORDS)
        for rec in p["records"]:
            rec["algorithm"] = 1
            rec["flags"] = 0
        self.assertTrue(audit(p)["passed"])

    def test_type_bitmap_validation(self) -> None:
        p = copy.deepcopy(RFC_PAYLOAD)
        p["records"] = copy.deepcopy(RFC_RECORDS)
        p["records"][0]["types"] = ["NSEC3", "NSEC3"]
        with self.assertRaises(VerificationFailure) as ctx:
            audit(p)
        self.assertEqual(ctx.exception.code, "BAD_TYPE_BITMAP")
        p2 = copy.deepcopy(RFC_PAYLOAD)
        p2["records"] = copy.deepcopy(RFC_RECORDS)
        p2["records"][0]["types"] = ["NOPE"]
        with self.assertRaises(VerificationFailure) as ctx:
            audit(p2)
        self.assertEqual(ctx.exception.code, "BAD_TYPE_BITMAP")

    def test_wildcard_type_in_qname_rejected(self) -> None:
        p = copy.deepcopy(RFC_PAYLOAD)
        p["qname"] = "*.w.c.example"
        with self.assertRaises(VerificationFailure) as ctx:
            audit(p)
        self.assertEqual(ctx.exception.code, "BAD_NAME")


if __name__ == "__main__":
    unittest.main()
