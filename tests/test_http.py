"""端到端 HTTP 测试：在临时端口启动真实服务，覆盖健康、提交、重开、复用拒绝。"""

import json
import tempfile
import threading
import unittest
import urllib.error
import urllib.request

from app.server import build_server

RFC_PAYLOAD = {
    "audit_id": "HTTP-RFC",
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


class HttpTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.tmp = tempfile.TemporaryDirectory()
        cls.server = build_server(data_dir=cls.tmp.name, host="127.0.0.1", port=0)
        cls.port = cls.server.server_address[1]
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.server.shutdown()
        cls.server.server_close()
        cls.tmp.cleanup()

    def _request(self, method: str, path: str, obj=None):
        data = json.dumps(obj).encode() if obj is not None else None
        req = urllib.request.Request(
            f"http://127.0.0.1:{self.port}{path}", data=data, method=method,
            headers={"Content-Type": "application/json"} if data else {},
        )
        try:
            with urllib.request.urlopen(req, timeout=5) as resp:
                return resp.status, resp.headers.get("Content-Type"), resp.read()
        except urllib.error.HTTPError as e:
            return e.code, e.headers.get("Content-Type"), e.read()

    def test_health(self) -> None:
        code, ctype, body = self._request("GET", "/healthz")
        self.assertEqual(code, 200)
        self.assertIn("application/json", ctype)
        self.assertEqual(json.loads(body)["status"], "ok")

    def test_index_page(self) -> None:
        code, ctype, body = self._request("GET", "/")
        self.assertEqual(code, 200)
        self.assertIn("text/html", ctype)
        text = body.decode()
        for fragment in ["稳定审计标识", "规范域名", "目标名称", "NSEC3 盐值",
                         "owner 哈希", "类型位图"]:
            self.assertIn(fragment, text)

    def test_submit_pass_then_reopen_json_and_page(self) -> None:
        code, _, body = self._request("POST", "/api/audits", RFC_PAYLOAD)
        self.assertEqual(code, 201)
        record = json.loads(body)
        self.assertEqual(record["result"]["status"], "PASS")

        code, _, body = self._request("GET", "/api/audits/HTTP-RFC")
        self.assertEqual(code, 200)
        self.assertEqual(json.loads(body)["result"]["conclusion"], "NXDOMAIN_PROVEN")

        code, ctype, body = self._request("GET", "/audits/HTTP-RFC")
        self.assertEqual(code, 200)
        self.assertIn("text/html", ctype)
        page = body.decode()
        for fragment in [
            "PASS", "c.example", "w.c.example", "*.c.example",
            "WRAP_AROUND", "FORWARD", "最近存在祖先",
            "下一层名称", "通配符排除", "环绕方向", "逐祖先哈希复算表",
        ]:
            self.assertIn(fragment, page)

    def test_rejected_submission_records_reasons(self) -> None:
        bad = json.loads(json.dumps(RFC_PAYLOAD))
        bad["audit_id"] = "HTTP-MISS-WC"
        bad["records"] = [RFC_PAYLOAD["records"][1]]  # 只剩环绕边：CE 不存在
        code, _, body = self._request("POST", "/api/audits", bad)
        self.assertEqual(code, 201)  # 结论本身被冻结，只是状态为 REJECTED
        self.assertEqual(json.loads(body)["result"]["status"], "REJECTED")

    def test_illegal_record_returns_400(self) -> None:
        bad = json.loads(json.dumps(RFC_PAYLOAD))
        bad["audit_id"] = "HTTP-BAD32"
        bad["records"][0]["next_hash"] = "W" * 32
        code, _, body = self._request("POST", "/api/audits", bad)
        self.assertEqual(code, 400)
        self.assertEqual(json.loads(body)["error"]["code"], "ILLEGAL_BASE32HEX")

    def test_reused_audit_id_changed_payload_returns_409(self) -> None:
        baseline = json.loads(json.dumps(RFC_PAYLOAD))
        baseline["audit_id"] = "HTTP-REUSE"
        self.assertEqual(self._request("POST", "/api/audits", baseline)[0], 201)
        changed = baseline
        changed["iterations"] = 13
        code, _, body = self._request("POST", "/api/audits", changed)
        self.assertEqual(code, 409)
        self.assertEqual(json.loads(body)["error"]["code"], "AUDIT_ID_REUSED")

    def test_unknown_id_404(self) -> None:
        code, _, _ = self._request("GET", "/api/audits/NOPE")
        self.assertEqual(code, 404)
        code, _, _ = self._request("GET", "/audits/NOPE")
        self.assertEqual(code, 404)

    def test_bad_json_400(self) -> None:
        req = urllib.request.Request(
            f"http://127.0.0.1:{self.port}/api/audits",
            data=b"{not json", method="POST",
            headers={"Content-Type": "application/json"},
        )
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            urllib.request.urlopen(req, timeout=5)
        self.assertEqual(ctx.exception.code, 400)


if __name__ == "__main__":
    unittest.main()
