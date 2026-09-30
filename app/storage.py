"""冻结结论的持久化存储（JSON 文件 + fcntl 行锁）。

离线控制网内无外部数据库；每条审计结论按稳定审计标识冻结为只读文件：
- 同一标识、同一归一化载荷重复提交：幂等返回已冻结结论；
- 同一标识但载荷改变：拒绝（AUDIT_ID_REUSED），不得覆盖原结论。
"""

from __future__ import annotations

import json
import os
import threading
import time
from typing import Any

try:  # fcntl 仅 POSIX 提供；离线控制网运行环境为 Linux
    import fcntl
except ImportError:  # pragma: no cover
    fcntl = None

from .verifier import VerificationFailure, audit, normalized_payload


class AuditIdReused(VerificationFailure):
    def __init__(self, audit_id: str):
        super().__init__(
            "AUDIT_ID_REUSED",
            f"审计标识 {audit_id!r} 已冻结过不同载荷的结论，标识不得复用",
        )


class JsonStore:
    def __init__(self, data_dir: str) -> None:
        self.data_dir = data_dir
        os.makedirs(self.data_dir, exist_ok=True)
        self._mem_lock = threading.Lock()

    def _path(self, audit_id: str) -> str:
        # AUDIT_ID_RE 已限定字符集，这里再防一次路径穿越
        safe = "".join(c if c.isalnum() or c in "_-" else "_" for c in audit_id)
        return os.path.join(self.data_dir, f"{safe}.json")

    def _lock_path(self) -> str:
        return os.path.join(self.data_dir, ".store.lock")

    def get(self, audit_id: str) -> dict[str, Any] | None:
        path = self._path(audit_id)
        if not os.path.exists(path):
            return None
        with open(path, "r", encoding="utf-8") as fh:
            return json.load(fh)

    def submit(self, payload: dict[str, Any]) -> tuple[dict[str, Any], bool]:
        """提交审计。返回 (冻结记录, 是否本次新建)。

        载荷归一化签名只取决于参数与记录内容，不受字段顺序或大小写影响。
        """
        signature = normalized_payload(payload)
        audit_id = payload["audit_id"]
        path = self._path(audit_id)

        with self._mem_lock:
            lock_fh = open(self._lock_path(), "a+")
            try:
                if fcntl is not None:
                    fcntl.flock(lock_fh.fileno(), fcntl.LOCK_EX)
                existing = self.get(audit_id)
                if existing is not None:
                    if existing["payload_signature"] != signature:
                        raise AuditIdReused(audit_id)
                    return existing, False

                result = audit(payload)
                record = {
                    "frozen_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                    "payload_signature": signature,
                    "submitted_payload": payload,
                    "result": result,
                }
                tmp = path + ".tmp"
                with open(tmp, "w", encoding="utf-8") as fh:
                    json.dump(record, fh, ensure_ascii=False, indent=2)
                os.replace(tmp, path)
                return record, True
            finally:
                if fcntl is not None:
                    fcntl.flock(lock_fh.fileno(), fcntl.LOCK_UN)
                lock_fh.close()

    def list_ids(self) -> list[str]:
        return sorted(
            fn[:-5]
            for fn in os.listdir(self.data_dir)
            if fn.endswith(".json")
        )
