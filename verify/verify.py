"""Acceptance runner for the `verify` compose service.

Runs (in order):
  1. unit tests (crypto vectors, chain rules, store semantics)
  2. HTTP smoke (UI page, health endpoint)
  3. API smoke (demo packages, inspect)
  4. scenario: valid execution + idempotent retry
  5. scenario: concurrent retransmission converges to one execution/receipt
  6. scenario: single-use leaf, tamper / scope / expiry / revocation rejection
     with no execution records left behind

Exits 0 when everything passes, 1 otherwise.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request

APP_URL = os.environ.get("APP_URL", "http://127.0.0.1:8000").rstrip("/")
RESULTS = []


def record(name, ok, detail=""):
    RESULTS.append((name, ok, detail))
    mark = "PASS" if ok else "FAIL"
    print(f"[{mark}] {name}" + (f" — {detail}" if detail else ""), flush=True)


def http(method, path, body=None):
    data = json.dumps(body).encode("utf-8") if body is not None else None
    req = urllib.request.Request(
        APP_URL + path,
        data=data,
        method=method,
        headers={"Content-Type": "application/json"} if data else {},
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        raw = exc.read().decode("utf-8")
        try:
            return exc.code, json.loads(raw)
        except json.JSONDecodeError:
            return exc.code, {"raw": raw}


def http_raw(path):
    with urllib.request.urlopen(APP_URL + path, timeout=30) as resp:
        return resp.status, resp.read()


def run_unit_tests():
    proc = subprocess.run(
        [sys.executable, "-m", "unittest", "discover", "-s", "tests", "-v"],
        capture_output=True,
        text=True,
        cwd=os.environ.get("APP_ROOT", "/srv"),
    )
    tail = (proc.stderr or proc.stdout).strip().splitlines()[-1:]
    record("unit: 单元测试（Ed25519 向量/链规则/存储）", proc.returncode == 0, tail[0] if tail else "")
    return proc.returncode == 0


def wait_for_health():
    for _ in range(60):
        try:
            status, data = http("GET", "/healthz")
            if status == 200 and data.get("status") == "ok":
                record("smoke: 健康响应 /healthz", True)
                return True
        except Exception:
            pass
        time.sleep(1)
    record("smoke: 健康响应 /healthz", False, "app never became healthy")
    return False


def scenario_valid_execution():
    _, demo = http("GET", "/api/demo")
    sc = demo["scenarios"]["valid"]
    body = {"package": sc["package"], "request": sc["request"]}

    status, inspect = http("POST", "/api/inspect", body)
    record("api: 有效包逐级检查通过", status == 200 and inspect.get("ok") is True,
           str(inspect.get("first_error")))

    status, first = http("POST", "/api/execute", body)
    ok = status == 200 and first.get("ok") and first.get("replay") is False
    record("场景: 有效执行返回回执", ok, f"HTTP {status}")
    if not ok:
        return None

    status, retry = http("POST", "/api/execute", body)
    same = (
        status == 200
        and retry.get("replay") is True
        and retry.get("receipt") == first.get("receipt")
    )
    record("场景: 响应丢失后重试返回同一回执", same)

    _, verdicts = http("GET", "/api/verdicts")
    found = any(
        v["verdict_key"] == first["receipt"]["verdict_key"]
        and v["receipt"] == first["receipt"]
        for v in verdicts.get("verdicts", [])
    )
    record("场景: 裁决已持久化可复核", found)
    return first["receipt"]


def scenario_concurrent_retransmission():
    _, demo = http("GET", "/api/demo")
    sc = demo["scenarios"]["valid"]
    body = {"package": sc["package"], "request": sc["request"]}
    results = [None] * 8

    def worker(i):
        results[i] = http("POST", "/api/execute", body)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    receipts = [json.dumps(r[1].get("receipt"), sort_keys=True) for r in results]
    statuses = [r[0] for r in results]
    firsts = [r for r in results if r[1].get("replay") is False]
    one_receipt = len(set(receipts)) == 1 and all(r[1].get("ok") for r in results)
    record(
        "场景: 并发重传收敛为一次执行与同一回执",
        all(s == 200 for s in statuses) and one_receipt and len(firsts) == 1,
        f"statuses={statuses}, distinct_receipts={len(set(receipts))}, firsts={len(firsts)}",
    )

    # Same leaf, different request -> single-use rejection, no new record.
    other = {"package": sc["package"], "request": dict(sc["request"], params={"delay_seconds": 9})}
    status, reused = http("POST", "/api/execute", other)
    record(
        "场景: 已使用末级凭据不能再次驱动设备",
        status == 409 and reused.get("code") == "leaf-already-used",
        f"HTTP {status}",
    )
    _, verdicts = http("GET", "/api/verdicts")
    count = sum(1 for v in verdicts.get("verdicts", []) if v["leaf_key"] == reused["report"]["summary"]["leaf_key"])
    record("场景: 单次使用叶凭据仅留下一条执行记录", count == 1, f"records={count}")


def scenario_rejections():
    _, demo = http("GET", "/api/demo")
    _, before = http("GET", "/api/verdicts")
    before_count = len(before.get("verdicts", []))

    cases = [
        ("篡改拒绝", "tampered", "signature"),
        ("越权命令拒绝", "out_of_scope", "scope"),
        ("过期拒绝", "expired", "expired"),
        ("有效撤销声明拒绝", "revoked", "revoked"),
    ]
    for name, key, needle in cases:
        sc = demo["scenarios"][key]
        status, resp = http("POST", "/api/execute", {"package": sc["package"], "request": sc["request"]})
        rejected = status == 400 and resp.get("ok") is False and resp.get("error")
        record(f"场景: {name}", bool(rejected), f"HTTP {status} code={resp.get('code')}")

    _, after = http("GET", "/api/verdicts")
    after_count = len(after.get("verdicts", []))
    record(
        "场景: 被拒绝项不留下执行记录",
        after_count == before_count,
        f"before={before_count} after={after_count}",
    )


def http_smoke():
    try:
        status, body = http_raw("/")
        record("smoke: 操作员页面 /", status == 200 and "委托包核验台".encode("utf-8") in body)
    except Exception as exc:
        record("smoke: 操作员页面 /", False, str(exc))
    status, demo = http("GET", "/api/demo")
    record(
        "smoke: 演练包接口 /api/demo",
        status == 200 and set(demo.get("scenarios", {})) >= {"valid", "tampered", "revoked"},
    )


def main():
    print(f"verify: target={APP_URL}", flush=True)
    unit_ok = run_unit_tests()
    if not wait_for_health():
        record("verify 总体", False, "app unhealthy")
        return 1
    http_smoke()
    scenario_valid_execution()
    scenario_concurrent_retransmission()
    scenario_rejections()

    failed = [r for r in RESULTS if not r[1]]
    print(f"\nverify: {len(RESULTS) - len(failed)}/{len(RESULTS)} checks passed", flush=True)
    if failed or not unit_ok:
        for name, _, detail in failed:
            print(f"  FAILED: {name} {detail}", flush=True)
        return 1
    print("verify: ALL CHECKS PASSED", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
