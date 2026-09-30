"""离线 NSEC3 审计 HTTP 服务（仅依赖 Python 标准库）。

路由：
- GET  /healthz                 健康检查
- GET  /                        审计提交页面
- POST /api/audits              提交记录组并冻结结论（JSON）
- GET  /api/audits              列出全部审计标识
- GET  /api/audits/<id>         读取冻结结论（JSON）
- GET  /audits/<id>             按标识重新打开已冻结结论（并列展示页面）
"""

from __future__ import annotations

import html
import json
import os
import re
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

from .storage import AuditIdReused, JsonStore
from .verifier import VerificationFailure

DATA_DIR = os.environ.get("AUDIT_DATA_DIR", "/data")
BIND_HOST = os.environ.get("AUDIT_BIND", "0.0.0.0")
BIND_PORT = int(os.environ.get("AUDIT_PORT", "8080"))

_PAGE_HEAD = """<!doctype html>
<html lang="zh-CN"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>NSEC3 不存在证明离线审计</title>
<style>
:root{--bg:#0f1620;--panel:#18222f;--ink:#e6edf3;--muted:#93a4b4;
--ok:#2ea043;--bad:#d1242f;--line:#2b3a4a;--accent:#2f81f7}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--ink);
font:14px/1.6 "Segoe UI","PingFang SC","Microsoft YaHei",sans-serif}
header{padding:18px 28px;border-bottom:1px solid var(--line);
background:var(--panel);display:flex;align-items:baseline;gap:14px;flex-wrap:wrap}
header h1{font-size:17px;margin:0}
header .sub{color:var(--muted);font-size:12px}
main{max-width:1280px;margin:0 auto;padding:22px 28px 60px}
.grid{display:grid;grid-template-columns:minmax(0,1fr) minmax(0,1fr);gap:18px}
@media(max-width:960px){.grid{grid-template-columns:1fr}}
.card{background:var(--panel);border:1px solid var(--line);border-radius:8px;padding:16px 18px}
.card h2{font-size:14px;margin:0 0 12px;color:var(--accent)}
label{display:block;font-size:12px;color:var(--muted);margin:10px 0 3px}
input,textarea{width:100%;background:#0d141c;border:1px solid var(--line);
color:var(--ink);border-radius:5px;padding:7px 9px;font-family:ui-monospace,Consolas,monospace;font-size:13px}
input:focus,textarea:focus{outline:1px solid var(--accent)}
button{background:var(--accent);color:#fff;border:0;border-radius:5px;
padding:8px 18px;font-size:13px;cursor:pointer;margin-top:14px}
button.secondary{background:#304256}
.row2{display:grid;grid-template-columns:1fr 130px;gap:10px}
.rec{border:1px solid var(--line);border-radius:6px;padding:10px;margin-bottom:10px;background:#0d141c}
.rec .rhead{display:flex;justify-content:space-between;color:var(--muted);font-size:12px;margin-bottom:6px}
.rec button{margin:6px 0 0;padding:3px 10px;background:#3d2030}
.badge{display:inline-block;padding:2px 9px;border-radius:11px;font-size:12px;font-weight:600}
.badge.PASS{background:rgba(46,160,67,.18);color:#56d364}
.badge.REJECTED{background:rgba(209,36,47,.18);color:#ff7b72}
.kv{font-family:ui-monospace,Consolas,monospace;font-size:12px;word-break:break-all}
.kv td{padding:3px 8px 3px 0;vertical-align:top}
.kv td.k{color:var(--muted);white-space:nowrap}
.mono{font-family:ui-monospace,Consolas,monospace;font-size:12px;word-break:break-all}
table.ev{width:100%;border-collapse:collapse;font-size:12px}
table.ev th,table.ev td{border:1px solid var(--line);padding:6px 8px;text-align:left;vertical-align:top}
table.ev th{color:var(--muted);font-weight:500;background:#0d141c}
.fact{font-size:11px;border:1px solid var(--line);border-radius:3px;padding:0 6px;margin:1px 2px 1px 0;display:inline-block}
.reject{border-left:3px solid var(--bad);padding:6px 10px;background:rgba(209,36,47,.08);
margin:5px 0;font-size:12px;border-radius:0 4px 4px 0}
.wrap-FORWARD{color:#79c0ff}.wrap-WRAP_AROUND{color:#ffa657}.wrap-SELF_LOOP{color:#ff7b72}
.muted{color:var(--muted)}
a{color:var(--accent)}
.pill{font-size:11px;border:1px solid var(--line);border-radius:10px;padding:1px 8px;color:var(--muted)}
</style></head><body>
<header><h1>NSEC3 不存在证明离线审计</h1>
<span class="sub">RFC 5155 / RFC 7129 · 仅 SHA-1 · 无 Opt-Out · 环形半开区间 (owner, next] · 离线控制网</span></header><main>
"""

_PAGE_FOOT = "</main></body></html>"

_FORM_JS = """
<script>
let recIdx = 1;
function addRecord(p) {
  p = p || {owner_hash:'', next_hash:'', types:'NSEC3,RRSIG'};
  const idx = recIdx++;
  const div = document.createElement('div');
  div.className = 'rec';
  div.dataset.idx = idx;
  div.innerHTML = `<div class="rhead"><span>记录 #${idx}</span>
    <button type="button" onclick="this.closest('.rec').remove()">删除</button></div>
    <label>owner 哈希（Base32hex，32 字符）</label>
    <input class="f-owner" value="${p.owner_hash||''}">
    <label>next 哈希</label>
    <input class="f-next" value="${p.next_hash||''}">
    <label>类型位图（逗号分隔，如 NSEC3,RRSIG）</label>
    <input class="f-types" value="${p.types||''}">`;
  document.getElementById('recs').appendChild(div);
}
function collect(){
  const v = id => document.getElementById(id).value.trim();
  return {
    audit_id: v('audit_id'), zone: v('zone'), qname: v('qname'),
    salt: v('salt'), iterations: parseInt(v('iterations')||'0',10),
    records: [...document.querySelectorAll('.rec')].map(d => ({
      owner_hash: d.querySelector('.f-owner').value.trim(),
      next_hash: d.querySelector('.f-next').value.trim(),
      types: d.querySelector('.f-types').value.split(',').map(s=>s.trim()).filter(Boolean)
    }))
  };
}
async function submit(){
  const out = document.getElementById('out');
  out.textContent = '正在审计并冻结…';
  try{
    const r = await fetch('/api/audits',{method:'POST',
      headers:{'Content-Type':'application/json'}, body: JSON.stringify(collect())});
    const j = await r.json();
    if(j.error){ out.textContent = (j.error.code||'')+' '+j.error.message; }
    else { window.location.href = '/audits/'+encodeURIComponent(j.result.audit_id); }
  }catch(e){ out.textContent = '请求失败：'+e; }
}
addRecord();
</script>
"""


def _index_page() -> str:
    return _PAGE_HEAD + """
<div class="grid">
  <section class="card">
    <h2>提交审计载荷</h2>
    <form onsubmit="event.preventDefault();submit()">
      <label>稳定审计标识（audit_id，冻结后可凭其重新打开）</label>
      <input id="audit_id" required pattern="[A-Za-z0-9_-]{1,64}" placeholder="SAT-MISSION-20260930-01">
      <div class="row2">
        <div><label>规范域名（区域，zone）</label><input id="zone" placeholder="mission.example.test"></div>
        <div><label>迭代次数</label><input id="iterations" type="number" min="0" max="65535" value="12"></div>
      </div>
      <label>目标名称（qname）</label><input id="qname" placeholder="host.svc.mission.example.test">
      <label>NSEC3 盐值（十六进制，空盐留空）</label><input id="salt" placeholder="aabbccdd">
      <label style="margin-top:14px">记录组（owner 哈希、next 哈希、类型位图）</label>
      <div id="recs"></div>
      <button type="button" class="secondary" onclick="addRecord()">追加一条记录</button>
      <div><button type="submit">审计并冻结结论</button></div>
      <p id="out" class="mono" style="color:#ff7b72"></p>
    </form>
  </section>
  <section class="card">
    <h2>按标识重新打开已冻结结论</h2>
    <form action="/audits/goto" method="get">
      <label>稳定审计标识</label>
      <input name="id" required pattern="[A-Za-z0-9_-]{1,64}" placeholder="SAT-MISSION-20260930-01">
      <button type="submit">打开</button>
    </form>
    <p class="muted" style="font-size:12px;margin-top:16px">
    判定规则：① 逐祖先精确复算 SHA-1 迭代哈希，取最深命中 owner 者为最近存在祖先 CE；
    ② 下一层名称 NC 必须被某条 NSEC3 的半开区间 (owner, next] 覆盖（不得命中 owner）；
    ③ 通配符 <span class="mono">*.CE</span> 必须被另一区间覆盖。三者齐备方可判 NXDOMAIN。
    重复 owner、断言冲突、非法 Base32hex、截断哈希、标识复用而载荷改变、证据不足一律拒绝。</p>
  </section>
</div>
""" + _FORM_JS + _PAGE_FOOT


def _kv(rows: list[tuple[str, str]]) -> str:
    body = "".join(
        f"<tr><td class='k'>{html.escape(k)}</td><td>{v}</td></tr>" for k, v in rows
    )
    return f'<table class="kv">{body}</table>'


def _cover_panel(title: str, ev: dict | None) -> str:
    if not ev:
        return (
            f"<section class='card'><h2>{title}</h2>"
            "<p class='muted'>无此项证据（最近存在祖先未确定）。</p></section>"
        )
    h = html.escape
    if ev.get("covered_by") is None:
        body = (
            "<p style='color:#ff7b72'>未被任何提交记录的半开哈希区间覆盖 —— "
            "证据不足，不得据此判定 NXDOMAIN。</p>"
        )
    else:
        cb = ev["covered_by"]
        rec = cb["record"]
        body = _kv([
            ("名称", f"<b>{h(ev['name'])}</b>"),
            ("迭代哈希", h(ev["hash_b32hex"])),
            ("覆盖记录", f"#{rec['index']}"),
            ("owner 哈希", h(rec["owner_hash"])),
            ("next 哈希", h(rec["next_hash"])),
            ("环绕方向", f"<span class='wrap-{rec['wrap_direction']}'>{rec['wrap_direction']}</span>"),
            ("区间", h(cb["ordering"]["half_open_interval"])),
        ])
    return f"<section class='card'><h2>{title}</h2>{body}</section>"


def _records_table(record_list: list[dict]) -> str:
    head = (
        "<table class='ev'><tr><th>#</th><th>owner 哈希</th><th>next 哈希</th>"
        "<th>环绕方向</th><th>类型位图</th><th>承担事实</th></tr>"
    )
    rows = []
    for r in record_list:
        facts = "".join(f"<span class='fact'>{f}</span>" for f in r.get("facts", []))
        rows.append(
            "<tr{hl}><td>{i}</td><td class='mono'>{o}</td><td class='mono'>{n}</td>"
            "<td><span class='wrap-{d}'>{d}</span></td><td class='mono'>{t}</td>"
            "<td>{f}</td></tr>".format(
                hl=" style='background:rgba(47,129,247,.08)'" if r.get("facts") else "",
                i=r["index"], o=html.escape(r["owner_hash"]), n=html.escape(r["next_hash"]),
                d=r["wrap_direction"], t=html.escape(", ".join(r["types"])) or "—", f=facts,
            )
        )
    return head + "".join(rows) + "</table>"


def _ancestors_table(rows: list[dict]) -> str:
    head = (
        "<table class='ev'><tr><th>祖先名称（顶点 → 目标）</th>"
        "<th>精确迭代哈希（Base32hex）</th><th>角色</th></tr>"
    )
    body = "".join(
        "<tr><td class='mono'>{n}</td><td class='mono'>{h}</td><td>{r}</td></tr>".format(
            n=html.escape(x["name"]), h=html.escape(x["hash_b32hex"]),
            r={"CLOSEST_ENCLOSER": "<b style='color:#56d364'>最近存在祖先 CE</b>",
               "NEXT_CLOSER": "<b style='color:#79c0ff'>下一层名称 NC</b>"}.get(x["role"], x["role"]),
        )
        for x in rows
    )
    return head + body + "</table>"


def render_frozen(record: dict) -> str:
    r = record["result"]
    ev = r["evidence"]
    p = r["parameters"]
    h = html.escape
    ce = ev["closest_encloser"]
    ce_body = (
        _kv([
            ("最近存在祖先", f"<b>{h(ce['name'])}</b>"),
            ("迭代哈希", h(ce["hash_b32hex"])),
            ("命中记录", f"#{ce['matched_record_index']}"),
            ("owner 哈希", h(ce["matched_record"]["owner_hash"])),
        ])
        if ce
        else "<p style='color:#ff7b72'>祖先链上无任何名称命中记录 owner。</p>"
    )
    reasons = "".join(
        f"<div class='reject'><b>{h(x['code'])}</b>：{h(x['message'])}"
        + (f"（记录 #{x['record_index']}）" if x.get("record_index") is not None else "")
        + "</div>"
        for x in r["rejection_reasons"]
    ) or '<p class="muted">无。三项事实齐备，NXDOMAIN 证明成立。</p>'

    top = f"""
<div class="card" style="margin-bottom:18px">
  <h2 style="display:inline-block">审计结论</h2>
  <span class="badge {r['status']}">{r['status']} · {h(r['conclusion'])}</span>
  <span class="pill">标识 {h(r['audit_id'])}</span>
  <span class="pill">冻结于 {h(record['frozen_at'])}</span>
  {_kv([
    ("区域 / 目标", f"{h(p['zone'])} <b>→</b> {h(p['qname'])}"),
    ("哈希算法 / Opt-Out", f"{h(p['hash_algorithm'])}（algorithm=1） / {'是' if p['opt_out'] else '否（flags=0）'}"),
    ("盐值（hex） / 迭代", f"{h(p['salt_hex']) or '（空）'} / {p['iterations']}"),
    ("载荷归一化签名", f"<span class='mono'>{h(record['payload_signature'][:160])}…</span>"),
  ])}
</div>
<div class="grid" style="margin-bottom:18px">
  <section class="card"><h2>最近存在祖先（Closest Encloser）</h2>{ce_body}</section>
  {_cover_panel('被覆盖名称 ① 下一层名称（Next Closer）', ev['next_closer'])}
  {_cover_panel('被覆盖名称 ② 通配符排除（*.CE）', ev['wildcard'])}
</div>
"""
    detail = f"""
<div class="card" style="margin-bottom:18px"><h2>拒绝/冲突原因（如有）</h2>{reasons}</div>
<div class="card" style="margin-bottom:18px">
  <h2>所用记录与环绕方向（承担事实高亮）</h2>{_records_table(ev['records_used'])}
  <h2 style="margin-top:18px">提交的全部记录</h2>{_records_table(ev['all_records'])}
</div>
<div class="grid">
  <div class="card"><h2>逐祖先哈希复算表</h2>{_ancestors_table(ev['ancestors'])}</div>
  <div class="card"><h2>环形区间语义</h2>
    <table class="kv">
      <tr><td class='k'>区间</td><td class="mono">(owner, next]，环模 2^160</td></tr>
      <tr><td class='k'>正向 FORWARD</td><td class="mono">owner &lt; hash ≤ next</td></tr>
      <tr><td class='k'>环绕 WRAP_AROUND</td><td class="mono">hash &gt; owner 或 hash ≤ next（跨零）</td></tr>
      <tr><td class='k'>命中先于覆盖</td><td>哈希等于任一 owner 时只能判定“存在”，绝不按覆盖处理</td></tr>
    </table>
    <p class="muted" style="font-size:12px;margin-top:10px">审查员可凭上方名称、盐值与迭代次数
    使用 H0=SHA1(wire‖salt)、H(k)=SHA1(H(k−1)‖salt) 独立复算。</p>
  </div>
</div>
<p class="muted" style="margin-top:16px"><a href="/">← 返回提交页</a>
&nbsp;|&nbsp; <a href="/api/audits/{h(r['audit_id'])}">读取 JSON 结论</a></p>
"""
    return _PAGE_HEAD + top + detail + _PAGE_FOOT


class Handler(BaseHTTPRequestHandler):
    server_version = "Nsec3Audit/1.0"

    def log_message(self, fmt: str, *args) -> None:  # 静默默认日志
        pass

    def _send_json(self, code: int, obj: dict) -> None:
        body = json.dumps(obj, ensure_ascii=False, indent=2).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_html(self, code: int, text: str) -> None:
        body = text.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        path = parsed.path
        store: JsonStore = self.server.store  # type: ignore[attr-defined]

        if path == "/healthz":
            self._send_json(200, {"status": "ok", "service": "nsec3-audit"})
            return
        if path == "/":
            self._send_html(200, _index_page())
            return
        if path == "/api/audits":
            self._send_json(200, {"audit_ids": store.list_ids()})
            return
        m = re.fullmatch(r"/api/audits/([A-Za-z0-9_-]{1,64})", path)
        if m:
            rec = store.get(m.group(1))
            if rec is None:
                self._send_json(404, {"error": {"code": "NOT_FOUND", "message": "审计标识不存在"}})
            else:
                self._send_json(200, rec)
            return
        m = re.fullmatch(r"/audits/([A-Za-z0-9_-]{1,64})", path)
        if m:
            rec = store.get(m.group(1))
            if rec is None:
                self._send_html(404, _PAGE_HEAD + "<p>审计标识不存在。 <a href='/'>返回</a></p>" + _PAGE_FOOT)
            else:
                self._send_html(200, render_frozen(rec))
            return
        if path == "/audits/goto":
            from urllib.parse import parse_qs
            qs = parse_qs(parsed.query)
            aid = qs.get("id", [""])[0]
            self.send_response(302)
            self.send_header("Location", f"/audits/{aid}")
            self.end_headers()
            return
        self._send_json(404, {"error": {"code": "NOT_FOUND", "message": "未知路由"}})

    def do_POST(self) -> None:
        parsed = urlparse(self.path)
        if parsed.path != "/api/audits":
            self._send_json(404, {"error": {"code": "NOT_FOUND", "message": "未知路由"}})
            return
        length = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(length) if length else b""
        try:
            payload = json.loads(raw.decode("utf-8"))
            if not isinstance(payload, dict):
                raise ValueError("载荷必须是 JSON 对象")
        except (ValueError, UnicodeDecodeError) as exc:
            self._send_json(400, {"error": {"code": "BAD_JSON", "message": f"JSON 解析失败: {exc}"}})
            return
        try:
            record, created = self.server.store.submit(payload)  # type: ignore[attr-defined]
        except AuditIdReused as exc:
            self._send_json(409, {"error": {"code": exc.code, "message": exc.message}})
            return
        except VerificationFailure as exc:
            self._send_json(400, {"error": {"code": exc.code, "message": exc.message,
                                           "record_index": exc.record_index}})
            return
        self._send_json(201 if created else 200, record)


def build_server(data_dir: str = DATA_DIR, host: str = BIND_HOST, port: int = BIND_PORT) -> ThreadingHTTPServer:
    server = ThreadingHTTPServer((host, port), Handler)
    server.store = JsonStore(data_dir)  # type: ignore[attr-defined]
    return server


def main() -> None:
    server = build_server()
    print(f"nsec3-audit listening on {BIND_HOST}:{BIND_PORT}, data={DATA_DIR}", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
