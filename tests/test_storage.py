"""冻结存储测试：幂等重放、标识复用而载荷改变、大小写/顺序归一化。"""

import copy
import tempfile
import unittest

from app.storage import AuditIdReused, JsonStore

PAYLOAD = {
    "audit_id": "FROZEN-1",
    "zone": "example",
    "qname": "x.w.c.example",
    "salt": "aabbccdd",
    "iterations": 12,
    "records": [
        {"owner_hash": "4G6P9U5GVFSHP30PQECJ98B3MAQBN1CK",
         "next_hash": "B76EQLMTQ7S6IULHLPOQGM1COPU2PCA6",
         "types": ["NS", "DS", "RRSIG"]},
        {"owner_hash": "U5KHQI4917VS9CA7IRC0TOT78AM6208L",
         "next_hash": "0P9MHAVEQVM6T7VBL5LOP2U3T2RP3TOM",
         "types": ["RRSIG"]},
    ],
}


class StoreTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.store = JsonStore(self.tmp.name)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_freeze_and_reopen(self) -> None:
        record, created = self.store.submit(copy.deepcopy(PAYLOAD))
        self.assertTrue(created)
        self.assertEqual(record["result"]["status"], "PASS")
        reopened = self.store.get("FROZEN-1")
        self.assertIsNotNone(reopened)
        self.assertEqual(reopened["frozen_at"], record["frozen_at"])

    def test_idempotent_replay(self) -> None:
        r1, c1 = self.store.submit(copy.deepcopy(PAYLOAD))
        r2, c2 = self.store.submit(copy.deepcopy(PAYLOAD))
        self.assertTrue(c1)
        self.assertFalse(c2)
        self.assertEqual(r1["payload_signature"], r2["payload_signature"])

    def test_audit_id_reuse_with_changed_payload_rejected(self) -> None:
        self.store.submit(copy.deepcopy(PAYLOAD))
        changed = copy.deepcopy(PAYLOAD)
        changed["salt"] = "00112233"  # 同标识、不同盐值
        with self.assertRaises(AuditIdReused) as ctx:
            self.store.submit(changed)
        self.assertEqual(ctx.exception.code, "AUDIT_ID_REUSED")
        # 原结论未被覆盖
        self.assertEqual(self.store.get("FROZEN-1")["submitted_payload"]["salt"], "aabbccdd")

    def test_signature_normalizes_case_order_and_types(self) -> None:
        self.store.submit(copy.deepcopy(PAYLOAD))
        reordered = copy.deepcopy(PAYLOAD)
        reordered["records"] = list(reversed(reordered["records"]))
        reordered["zone"] = "EXAMPLE"
        reordered["qname"] = "X.W.C.EXAMPLE"
        reordered["records"][0]["types"] = sorted(reordered["records"][0]["types"])
        _, created = self.store.submit(reordered)
        self.assertFalse(created, "大小写、记录顺序、类型顺序差异不应视为载荷改变")

    def test_changed_record_is_different_payload(self) -> None:
        self.store.submit(copy.deepcopy(PAYLOAD))
        changed = copy.deepcopy(PAYLOAD)
        changed["records"][0]["next_hash"] = "4G6P9U5GVFSHP30PQECJ98B3MAQBN1CL"
        with self.assertRaises(AuditIdReused):
            self.store.submit(changed)

    def test_rejected_submission_is_still_frozen(self) -> None:
        bad = copy.deepcopy(PAYLOAD)
        bad["audit_id"] = "FROZEN-BAD"
        bad["records"] = [PAYLOAD["records"][1]]  # 证据不足
        record, created = self.store.submit(bad)
        self.assertTrue(created)
        self.assertEqual(record["result"]["status"], "REJECTED")
        self.assertTrue(self.store.get("FROZEN-BAD"))

    def test_list_ids(self) -> None:
        p2 = copy.deepcopy(PAYLOAD)
        p2["audit_id"] = "FROZEN-2"
        self.store.submit(copy.deepcopy(PAYLOAD))
        self.store.submit(p2)
        self.assertEqual(self.store.list_ids(), ["FROZEN-1", "FROZEN-2"])


if __name__ == "__main__":
    unittest.main()
