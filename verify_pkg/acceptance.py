#!/usr/bin/env python3
"""verify —— 一次性验收逻辑：构建检查、单元测试与 API/HTTP 冒烟穿插执行。

用法：
    python3 -m verify_pkg [--base-url http://host:port]

不提供 --base-url 时，在进程内临时端口启动真实 HTTP 服务进行端到端验收；
提供时（如 Compose 的 verify 服务）对已运行的服务做 HTTP 冒烟。
"""

from __future__ import annotations

import json
import sys
import tempfile
import time
import unittest
import urllib.error
import urllib.request
from typing import Any

PASS_PAYLOAD = {
    # RFC 5155 Appendix I.5：x.w.c.example 的合法 NXDOMAIN 证明（含环绕覆盖）
    "audit_id": "ACCEPT-PASS-RFC5155",
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


def step(no: int, title: str) -> None:
    print(f"\n[verify {no:02d}] {title}", flush=True)


def ok(msg: str) -> None:
    print(f"  ✓ {msg}", flush=True)


def fail(msg: str) -> None:
    print(f"  ✗ {msg}", flush=True)


def http(method: str, url: str, obj: Any = None, timeout: float = 5.0):
    data = json.dumps(obj).encode() if obj is not None else None
    req = urllib.request.Request(
        url, data=data, method=method,
        headers={"Content-Type": "application/json"} if data else {},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, json.loads(resp.read().decode()) if resp.length != 0 else {}
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read().decode())


def run_tests(names: list[str]) -> bool:
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    for name in names:
        suite.addTests(loader.loadTestsFromName(name))
    result = unittest.TextTestRunner(verbosity=1, stream=sys.stderr).run(suite)
    return result.wasSuccessful()


def build_checks() -> bool:
    import compileall

    if not compileall.compile_dir("app", quiet=1, maxlevels=10):
        return False
    if not compileall.compile_dir("verify_pkg", quiet=1):
        return False
    import app.nsec3  # noqa: F401
    import app.verifier  # noqa: F401
    import app.server  # noqa: F401
    import app.storage  # noqa: F401
    import verify_pkg  # noqa: F401
    return True


def wait_healthy(base_url: str, attempts: int = 30) -> bool:
    for _ in range(attempts):
        try:
            code, body = http("GET", f"{base_url}/healthz")
            if code == 200 and body.get("status") == "ok":
                return True
        except OSError:
            pass
        time.sleep(0.5)
    return False


def smoke_suite(base_url: str) -> bool:
    success = True

    # 4) 合法不存在证明（NC 由 WRAP_AROUND 覆盖、WC 由 FORWARD 覆盖）
    code, body = http("POST", f"{base_url}/api/audits", PASS_PAYLOAD)
    if code not in (200, 201) or body["result"]["status"] != "PASS":
        fail(f"合法 RFC5155 证明应通过，实际 HTTP {code} / {body.get('result',{}).get('status')}")
        success = False
    else:
        ev = body["result"]["evidence"]
        assert ev["next_closer"]["covered_by"]["wrap_direction"] == "WRAP_AROUND"
        assert ev["wildcard"]["covered_by"]["wrap_direction"] == "FORWARD"
        ok("合法不存在证明通过；NC=WRAP_AROUND、WC=FORWARD 覆盖已确认")

    # 6) 遗漏通配符覆盖：只保留承担 NC 环绕覆盖的那条
    miss_wc = json.loads(json.dumps(PASS_PAYLOAD))
    miss_wc["audit_id"] = "ACCEPT-MISS-WC"
    miss_wc["records"] = [PASS_PAYLOAD["records"][1]]
    code, body = http("POST", f"{base_url}/api/audits", miss_wc)
    reasons = [x["code"] for x in body["result"]["rejection_reasons"]]
    if code != 201 or body["result"]["status"] != "REJECTED" or \
            "INSUFFICIENT_EVIDENCE" not in reasons:
        fail(f"遗漏覆盖证据应拒绝，实际 HTTP {code} reasons={reasons}")
        success = False
    else:
        ok("遗漏通配符/祖先覆盖的证据被拒绝（REJECTED 且已冻结）")

    # 另一种遗漏：CE 在、WC 区间被截断
    miss_wc2 = json.loads(json.dumps(PASS_PAYLOAD))
    miss_wc2["audit_id"] = "ACCEPT-MISS-WC2"
    miss_wc2["records"] = [
        {"owner_hash": "4G6P9U5GVFSHP30PQECJ98B3MAQBN1CK",
         "next_hash": "5" + "0" * 31, "types": ["NS"]},
        PASS_PAYLOAD["records"][1],
    ]
    code, body = http("POST", f"{base_url}/api/audits", miss_wc2)
    reasons = [x["code"] for x in body["result"]["rejection_reasons"]]
    if body["result"]["status"] != "REJECTED" or "MISSING_WILDCARD_COVER" not in reasons:
        fail(f"截断通配符区间应拒绝，实际 reasons={reasons}")
        success = False
    else:
        ok("截断的通配符覆盖区间被拒绝（MISSING_WILDCARD_COVER）")

    # 8) 非法 Base32hex 记录 -> 400
    bad32 = json.loads(json.dumps(PASS_PAYLOAD))
    bad32["audit_id"] = "ACCEPT-BAD32"
    bad32["records"][0]["next_hash"] = "W" * 32
    code, body = http("POST", f"{base_url}/api/audits", bad32)
    if code != 400 or body["error"]["code"] != "ILLEGAL_BASE32HEX":
        fail(f"非法 Base32hex 应 400，实际 HTTP {code} {body.get('error')}")
        success = False
    else:
        ok("非法 Base32hex 记录返回 400 ILLEGAL_BASE32HEX")

    # 8b) 截断哈希 -> 400
    trunc = json.loads(json.dumps(PASS_PAYLOAD))
    trunc["audit_id"] = "ACCEPT-TRUNC"
    trunc["records"][1]["owner_hash"] = "U5KHQI49"
    code, body = http("POST", f"{base_url}/api/audits", trunc)
    if code != 400 or body["error"]["code"] != "TRUNCATED_HASH":
        fail(f"截断哈希应 400，实际 HTTP {code} {body.get('error')}")
        success = False
    else:
        ok("截断哈希记录返回 400 TRUNCATED_HASH")

    # 10) 按标识重新打开页面：并列展示 CE / NC / WC / 环绕方向 / 所用记录
    raw = urllib.request.urlopen(
        f"{base_url}/audits/ACCEPT-PASS-RFC5155", timeout=5).read().decode()
    fragments = [
        "最近存在祖先", "下一层名称", "通配符排除", "c.example", "w.c.example",
        "*.c.example", "WRAP_AROUND", "FORWARD", "逐祖先哈希复算表",
    ]
    missing_fragments = [f for f in fragments if f not in raw]
    if missing_fragments:
        fail(f"重开页面缺少并列证据: {missing_fragments}")
        success = False
    else:
        ok("按标识重新打开的页面并列展示 CE、两项被覆盖名称、记录与环绕方向")

    # 11) 标识复用但载荷改变 -> 409
    reused = json.loads(json.dumps(PASS_PAYLOAD))
    reused["iterations"] = 13
    code, body = http("POST", f"{base_url}/api/audits", reused)
    if code != 409 or body["error"]["code"] != "AUDIT_ID_REUSED":
        fail(f"标识复用载荷改变应 409，实际 HTTP {code} {body.get('error')}")
        success = False
    else:
        ok("审计标识复用但载荷改变被 409 拒绝，原冻结结论未被覆盖")

    # 列表接口
    code, body = http("GET", f"{base_url}/api/audits")
    if code != 200 or "ACCEPT-PASS-RFC5155" not in body["audit_ids"]:
        fail("审计列表接口异常")
        success = False
    else:
        ok("审计列表接口可列出已冻结标识")

    return success


def main(argv: list[str] | None = None) -> int:
    argv = argv if argv is not None else sys.argv[1:]
    base_url = None
    if argv and argv[0] == "--base-url":
        base_url = argv[1].rstrip("/")

    own_server = None
    own_thread = None
    try:
        if base_url is None:
            import threading
            from app.server import build_server
            tmp = tempfile.TemporaryDirectory()
            own_server = build_server(data_dir=tmp.name, host="127.0.0.1", port=0)
            port = own_server.server_address[1]
            base_url = f"http://127.0.0.1:{port}"
            own_thread = threading.Thread(target=own_server.serve_forever, daemon=True)
            own_thread.start()
            print(f"[verify] 进程内验收服务已启动：{base_url}", flush=True)

        print("=" * 64)
        print(" NSEC3 不存在证明审计服务 —— 一次性验收")
        print("=" * 64)

        step(1, "构建检查：字节码编译与关键模块导入")
        if not build_checks():
            fail("构建检查失败")
            return 1
        ok("app/ 与 verify_pkg/ 编译通过，全部关键模块可导入")

        step(2, f"HTTP 冒烟：等待健康检查 {base_url}/healthz")
        if not wait_healthy(base_url):
            fail("健康检查不可达")
            return 1
        ok("健康检查 200 {status: ok}")

        step(3, "代码测试：NSEC3 原语（RFC 5155 官方向量 / Base32hex）")
        if not run_tests(["tests.test_nsec3"]):
            fail("NSEC3 原语测试失败")
            return 1
        ok("NSEC3 原语测试全部通过")

        step(4, "HTTP：合法不存在证明 + 环绕覆盖必须通过")
        # 与第 5 步的引擎测试穿插：这里先发一个合法证明
        code, body = http("POST", f"{base_url}/api/audits", PASS_PAYLOAD)
        if code != 201 or body["result"]["status"] != "PASS":
            fail(f"合法证明提交失败: HTTP {code}")
            return 1
        ok("合法证明已冻结为 PASS")

        step(5, "代码测试：判定引擎（CE/NC/WC、全部拒绝类别）")
        if not run_tests(["tests.test_verifier"]):
            fail("判定引擎测试失败")
            return 1
        ok("判定引擎测试全部通过")

        step(6, "HTTP：遗漏通配符覆盖、截断/非法记录、标识复用、重开页面")
        if not smoke_suite(base_url):
            return 1

        step(7, "构建检查（穿插）：存储/渲染模块二次导入与字节码复验")
        import compileall
        import app.storage  # noqa: F401
        import app.server as srv
        assert hasattr(srv, "render_frozen")
        if not compileall.compile_dir("app", quiet=1):
            fail("二次字节码编译失败")
            return 1
        ok("冻结存储、页面渲染模块可导入，字节码复验通过")

        step(8, "HTTP 终检前：非法记录拒绝结论已在上一步逐项确认")
        ok("ILLEGAL_BASE32HEX / TRUNCATED_HASH / MISSING_WILDCARD_COVER / 409 均符合预期")

        step(9, "代码测试：冻结存储与 HTTP 全链路")
        if not run_tests(["tests.test_storage", "tests.test_http"]):
            fail("存储/HTTP 测试失败")
            return 1
        ok("存储与 HTTP 测试全部通过")

        step(10, "HTTP 终检：健康地址与审计页可经配置端口访问")
        if not wait_healthy(base_url):
            fail("终检健康失败")
            return 1
        raw = urllib.request.urlopen(f"{base_url}/", timeout=5).read().decode()
        if "NSEC3 不存在证明离线审计" not in raw:
            fail("审计首页内容异常")
            return 1
        ok("健康地址与审计首页均可访问")

        print("\n" + "=" * 64)
        print(" 验收全部通过（合法证明通过、环绕覆盖确认、遗漏/非法均拒绝）")
        print("=" * 64)
        return 0
    finally:
        if own_server is not None:
            own_server.shutdown()
            own_server.server_close()


if __name__ == "__main__":
    raise SystemExit(main())
