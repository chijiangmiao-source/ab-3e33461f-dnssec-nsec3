"""verify：NSEC3 审计服务的一次性验收包（python -m verify）。

验收顺序刻意穿插构建检查、代码测试与 API/HTTP 冒烟：
  1) 构建检查：全量字节码编译 + 关键模块导入
  2) 等待 /healthz 健康
  3) 代码测试（nsec3 原语：RFC 向量）
  4) HTTP：提交合法 NXDOMAIN 证明（含环绕覆盖）→ 必须 PASS
  5) 代码测试（verifier 判定引擎全部拒绝类别）
  6) HTTP：遗漏通配符覆盖 → 冻结结论必须 REJECTED
  7) 构建检查：冻结存储与页面渲染模块导入
  8) HTTP：非法 Base32hex 记录 → 必须 400 拒绝
  9) 代码测试（存储 + HTTP 全链路）
 10) HTTP：按标识重新打开页面，并列证据必须齐全
 11) HTTP：标识复用但载荷改变 → 必须 409
 12) HTTP：健康地址可访问性终检

任一步失败即以非零退出码退出，全部通过退出 0。
"""

from .acceptance import main

if __name__ == "__main__":
    raise SystemExit(main())
