import argparse
import base64
import http.client
import json
import os
import shutil
import ssl
import tempfile
import threading
from collections import Counter
from urllib.parse import urlencode

from gm_hub_logging import verify_security_chain
from gm_hub_server import HubState, generate_ca_and_server_certs, start_https_server


def load_jsonl(path: str) -> list[dict]:
    items = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            if line.strip():
                items.append(json.loads(line))
    return items


def cmd_summary(log_dir: str) -> None:
    gen_files = sorted(f for f in os.listdir(log_dir) if f.startswith("gm_hub-") and f.endswith(".jsonl"))
    entries = []
    for fname in gen_files:
        entries.extend(load_jsonl(os.path.join(log_dir, fname)))

    levels = Counter(e.get("level") for e in entries)
    http_entries = [e for e in entries if e.get("event") == "http.access"]
    statuses = Counter(e.get("status") for e in http_entries)
    latencies = sorted(float(e.get("duration_ms", 0.0)) for e in http_entries)
    p50 = latencies[len(latencies) // 2] if latencies else 0.0
    p95 = latencies[min(len(latencies) - 1, int(len(latencies) * 0.95))] if latencies else 0.0
    alerts = [e for e in entries if e.get("event") == "alert.raised"]

    print(f"=== Зведення журналів ({len(gen_files)} файл, подій: {len(entries)}) ===")
    print("Рівні:", ", ".join(f"{k}={v}" for k, v in sorted(levels.items())))
    print("HTTP-запити:", len(http_entries), "| статуси:", ", ".join(f"{k}x{v}" for k, v in sorted(statuses.items())))
    print(f"Затримка: p50={p50:.2f} мс, p95={p95:.2f} мс")
    print(f"Сповіщення ({len(alerts)}):")
    for a in alerts:
        print(f"  {a['ts']} {a['level']} {a['rule']} subject={a['subject']} count={a['count']}")


def cmd_trace(log_dir: str, request_id: str) -> None:
    print(f"\n=== Кореляція за request_id={request_id} ===")
    for fname in sorted(os.listdir(log_dir)):
        if not fname.endswith(".jsonl"):
            continue
        for e in load_jsonl(os.path.join(log_dir, fname)):
            if e.get("request_id") == request_id:
                extra = {k: v for k, v in e.items() if k not in ("ts", "level", "event", "component", "version", "pid", "prev_hash", "entry_hash", "request_id")}
                print(f"  [{fname}] {e['ts']} {e['level']} {e['event']} {extra}")


def cmd_verify(log_dir: str) -> None:
    print("\n=== Перевірка цілісності безпекових журналів ===")
    for fname in sorted(os.listdir(log_dir)):
        if fname.startswith("gm_security-") and fname.endswith(".jsonl"):
            ok, cnt, errs = verify_security_chain(os.path.join(log_dir, fname))
            status = "OK (ланцюг SHA-256 цілий, витоків немає)" if ok else f"FAIL ({errs[0]})"
            print(f"  {fname}: записів={cnt} -> {status}")


def run_demo() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        ca_cert = os.path.join(tmp, "ca.pem")
        srv_cert = os.path.join(tmp, "srv.pem")
        srv_key = os.path.join(tmp, "srv.key")
        log_dir = os.path.join(tmp, "logs")
        generate_ca_and_server_certs(ca_cert, srv_cert, srv_key)

        state = HubState(log_dir=log_dir, token_ttl=600, max_failures=5, lock_seconds=300)
        gm_sec = state.add_client("oleksii-gm", "gm_admin")
        aud_sec = state.add_client("auditor-demo", "auditor")
        srv = start_https_server(state, srv_cert, srv_key, port=0)
        port = srv.server_address[1]
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        ctx = ssl.create_default_context(cafile=ca_cert)

        def req(method: str, path: str, headers=None, body=None):
            conn = http.client.HTTPSConnection("127.0.0.1", port, context=ctx, timeout=5)
            try:
                conn.request(method, path, body=body, headers=headers or {})
                r = conn.getresponse()
                raw = r.read().decode("utf-8", errors="replace")
                return r.status, dict(r.getheaders()), json.loads(raw) if raw else {}
            finally:
                conn.close()

        try:
            form = urlencode({"grant_type": "client_credentials"}).encode()
            b_aud = "Basic " + base64.b64encode(f"auditor-demo:{aud_sec}".encode()).decode()
            _, _, tok = req("POST", "/oauth/token", {"Authorization": b_aud, "Content-Type": "application/x-www-form-urlencoded"}, form)
            aud_token = tok["access_token"]

            # 1) Запит без токена -> отримаємо X-Request-ID для трасування
            _, h_401, _ = req("GET", "/api/v1/whoami")
            trace_id = h_401["X-Request-ID"]

            # 2) Імітація перебору (8 невдач) -> auth.lockout + auth.bruteforce_ip
            b_bad = "Basic " + base64.b64encode(b"intruder:wrong").decode()
            for _ in range(8):
                req("POST", "/oauth/token", {"Authorization": b_bad, "Content-Type": "application/x-www-form-urlencoded"}, form)

            # 3) Імітація сканування маршрутів (10 x 404) -> http.scan_404
            for i in range(10):
                req("GET", f"/api/v1/hidden_{i}")

            # 4) Отримання живих метрик аудитором
            st_m, _, metrics = req("GET", "/api/v1/metrics", {"Authorization": f"Bearer {aud_token}"})
            print(f"=== Живі метрики GET /api/v1/metrics [HTTP {st_m}] ===")
            print(json.dumps(metrics, ensure_ascii=False))

            cmd_summary(log_dir)
            cmd_trace(log_dir, trace_id)
            cmd_verify(log_dir)

            # 5) Демонстрація виявлення підміни в копії безпекового журналу
            sec_file = state.logger.security_log_path()
            copy_path = os.path.join(tmp, "security_tampered_copy.jsonl")
            shutil.copyfile(sec_file, copy_path)
            with open(copy_path, "r", encoding="utf-8") as f:
                lines = f.readlines()
            rec = json.loads(lines[4])
            rec["ip"] = "203.0.113.99"
            lines[4] = json.dumps(rec, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n"
            with open(copy_path, "w", encoding="utf-8") as f:
                f.writelines(lines)
            ok, cnt, errs = verify_security_chain(copy_path)
            print(f"\n=== Тест підміни поля ip у рядку 5 копії журналу ({cnt} записів) ===")
            print(f"  verify -> {ok} | {errs[0]}")
        finally:
            srv.shutdown()
            srv.server_close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Моніторинг та аналіз журналів gm_hub")
    parser.add_argument("--demo", action="store_true", help="Запустити демонстрацію моніторингу, трасування і перевірки цілісності")
    args = parser.parse_args()
    if args.demo:
        run_demo()