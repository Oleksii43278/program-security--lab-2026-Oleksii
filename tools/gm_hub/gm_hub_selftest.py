import base64
import http.client
import json
import os
import ssl
import tempfile
import threading
from urllib.parse import urlencode

from gm_hub_server import HubState, generate_ca_and_server_certs, sha256_hex, start_https_server


def basic_hdr(client_id: str, secret: str) -> str:
    raw = base64.b64encode(f"{client_id}:{secret}".encode("utf-8")).decode("ascii")
    return f"Basic {raw}"


def https_req(port: int, ctx: ssl.SSLContext, method: str, path: str, headers=None, body: bytes | None = None):
    conn = http.client.HTTPSConnection("127.0.0.1", port, context=ctx, timeout=5)
    try:
        conn.request(method, path, body=body, headers=headers or {})
        resp = conn.getresponse()
        raw = resp.read().decode("utf-8", errors="replace")
        data = json.loads(raw) if raw else {}
        return resp.status, dict(resp.getheaders()), data
    finally:
        conn.close()


def run_selftest() -> None:
    print("TaleSpire GM Hub 1.0.0 — комплексна самоперевірка клієнт-серверної безпеки")
    with tempfile.TemporaryDirectory() as tmp:
        ca_cert = os.path.join(tmp, "ca_cert.pem")
        srv_cert = os.path.join(tmp, "srv_cert.pem")
        srv_key = os.path.join(tmp, "srv_key.pem")
        ca_fp = generate_ca_and_server_certs(ca_cert, srv_cert, srv_key)

        bad_ca = os.path.join(tmp, "bad_ca.pem")
        generate_ca_and_server_certs(bad_ca, os.path.join(tmp, "b1.pem"), os.path.join(tmp, "b2.pem"))

        state = HubState(token_ttl=600, max_failures=5, lock_seconds=300)
        gm_sec = state.add_client("oleksii-gm", "gm_admin")
        player_sec = state.add_client("player-demo", "player_tester")
        auditor_sec = state.add_client("auditor-demo", "auditor")

        srv = start_https_server(state, srv_cert, srv_key, port=0)
        port = srv.server_address[1]
        t = threading.Thread(target=srv.serve_forever, daemon=True)
        t.start()

        ctx_ok = ssl.create_default_context(cafile=ca_cert)
        ctx_bad = ssl.create_default_context(cafile=bad_ca)

        passed = 0
        total = 16

        def check(num: int, title: str, cond: bool, detail: str) -> None:
            nonlocal passed
            assert cond, f"FAILED {num}: {title} ({detail})"
            passed += 1
            print(f"{num:2d}. OK  {title:<55} | {detail}")

        try:
            st, _, data = https_req(port, ctx_ok, "GET", "/api/v1/health")
            check(1, "TLS: /api/v1/health через HTTPS із перевіркою CA", st == 200, f"HTTP {st}, CA_FP={ca_fp}")

            tls_err = ""
            try:
                https_req(port, ctx_bad, "GET", "/api/v1/health")
            except ssl.SSLCertVerificationError as e:
                tls_err = type(e).__name__
            check(2, "TLS: відмова з чужим CA (захист від MITM)", tls_err == "SSLCertVerificationError", tls_err)

            plain_err = ""
            try:
                c = http.client.HTTPConnection("127.0.0.1", port, timeout=3)
                c.request("GET", "/api/v1/health")
                c.getresponse()
            except Exception as e:
                plain_err = type(e).__name__
            check(3, "TLS: відкритий HTTP на HTTPS-порт відхилено", bool(plain_err), plain_err)

            form_cc = urlencode({"grant_type": "client_credentials"}).encode()
            st1, h1, d1 = https_req(
                port, ctx_ok, "POST", "/oauth/token",
                {"Authorization": basic_hdr("oleksii-gm", "wrong-secret"), "Content-Type": "application/x-www-form-urlencoded"},
                form_cc,
            )
            check(4, "Auth: невірний секрет -> 401 + WWW-Authenticate", st1 == 401 and "Basic" in h1.get("WWW-Authenticate", ""), f"HTTP {st1} {d1.get('error')}")

            st2, _, d2 = https_req(
                port, ctx_ok, "POST", "/oauth/token",
                {"Authorization": basic_hdr("unknown-user", "wrong-secret"), "Content-Type": "application/x-www-form-urlencoded"},
                form_cc,
            )
            check(5, "Auth: неіснуючий клієнт -> ідентична відповідь 401", st2 == 401 and d1["error"] == d2["error"] and d1["message"] == d2["message"], f"HTTP {st2} {d2.get('error')}")

            form_body_sec = urlencode({"grant_type": "client_credentials", "client_id": "oleksii-gm", "client_secret": gm_sec}).encode()
            st3, _, d3 = https_req(port, ctx_ok, "POST", "/oauth/token", {"Content-Type": "application/x-www-form-urlencoded"}, form_body_sec)
            check(6, "Auth: секрет у тілі форми замість Basic -> 400", st3 == 400 and d3["error"] == "invalid_request", f"HTTP {st3} {d3.get('error')}")

            form_ropc = urlencode({"grant_type": "password"}).encode()
            st4, _, d4 = https_req(
                port, ctx_ok, "POST", "/oauth/token",
                {"Authorization": basic_hdr("oleksii-gm", gm_sec), "Content-Type": "application/x-www-form-urlencoded"},
                form_ropc,
            )
            check(7, "Auth: grant_type=password (ROPC) заборонено -> 400", st4 == 400 and d4["error"] == "unsupported_grant_type", f"HTTP {st4} {d4.get('error')}")

            st5, h5, d5 = https_req(
                port, ctx_ok, "POST", "/oauth/token",
                {"Authorization": basic_hdr("oleksii-gm", gm_sec), "Content-Type": "application/x-www-form-urlencoded"},
                form_cc,
            )
            gm_token = d5["access_token"]
            only_hash = gm_token not in state.tokens and sha256_hex(gm_token) in state.tokens
            check(8, "Token: Bearer 600s, no-store, у БД лише SHA-256", st5 == 200 and only_hash and h5.get("Cache-Control") == "no-store", f"HTTP 200, fp={sha256_hex(gm_token)[:12]}")

            form_bad_scope = urlencode({"grant_type": "client_credentials", "scope": "releases:write"}).encode()
            st6, _, d6 = https_req(
                port, ctx_ok, "POST", "/oauth/token",
                {"Authorization": basic_hdr("player-demo", player_sec), "Content-Type": "application/x-www-form-urlencoded"},
                form_bad_scope,
            )
            check(9, "Scope: запит понад роль (player -> releases:write)", st6 == 400 and d6["error"] == "invalid_scope", f"HTTP {st6} {d6.get('error')}")

            st7, h7, _ = https_req(port, ctx_ok, "GET", "/api/v1/whoami")
            st8, _, d8 = https_req(port, ctx_ok, "GET", "/api/v1/whoami", {"Authorization": "Bearer gmh_forged"})
            check(10, "Protected: без токена та з підробленим -> 401", st7 == 401 and st8 == 401 and "Bearer" in h7.get("WWW-Authenticate", ""), f"no-token={st7}, forged={st8} ({d8.get('error')})")

            st9, _, d9 = https_req(port, ctx_ok, "GET", "/api/v1/whoami", {"Authorization": f"Bearer {gm_token}"})
            check(11, "whoami: суб'єкт і роль визначено сервером із токена", st9 == 200 and d9["client_id"] == "oleksii-gm" and d9["role"] == "gm_admin", f"{d9['client_id']} / {d9['role']}")

            _, _, d_pl = https_req(
                port, ctx_ok, "POST", "/oauth/token",
                {"Authorization": basic_hdr("player-demo", player_sec), "Content-Type": "application/x-www-form-urlencoded"},
                form_cc,
            )
            player_token = d_pl["access_token"]
            rel_body = json.dumps({"version": "1.2.1", "product": "TaleSpire_GM_Logger_Pro", "sha256": "a" * 64, "tag": "v1.2.1"}).encode()
            st10, _, d10 = https_req(
                port, ctx_ok, "POST", "/api/v1/releases",
                {"Authorization": f"Bearer {player_token}", "Content-Type": "application/json"},
                rel_body,
            )
            check(12, "AuthZ: player-demo публікує реліз -> 403", st10 == 403 and d10["error"] == "insufficient_scope", f"HTTP {st10} {d10.get('error')}")

            st11, _, d11 = https_req(
                port, ctx_ok, "POST", "/api/v1/releases",
                {"Authorization": f"Bearer {gm_token}", "Content-Type": "application/json"},
                rel_body,
            )
            spoof_body = json.dumps({"version": "1.2.2", "published_by": "fake-admin"}).encode()
            st12, _, d12 = https_req(
                port, ctx_ok, "POST", "/api/v1/releases",
                {"Authorization": f"Bearer {gm_token}", "Content-Type": "application/json"},
                spoof_body,
            )
            st13, _, d13 = https_req(
                port, ctx_ok, "POST", "/api/v1/releases",
                {"Authorization": f"Bearer {gm_token}", "Content-Type": "application/json"},
                rel_body,
            )
            check(13, "Releases: 201 OK, підміна автора 400, дубль 409", st11 == 201 and st12 == 400 and st13 == 409, f"create={st11}, spoof={st12}, dup={st13}")

            st14, _, _ = https_req(port, ctx_ok, "POST", "/oauth/revoke", {"Authorization": f"Bearer {player_token}"})
            st15, _, d15 = https_req(port, ctx_ok, "GET", "/api/v1/whoami", {"Authorization": f"Bearer {player_token}"})
            check(14, "Revoke: відкликаний токен (RFC 7009) -> 401", st14 == 200 and st15 == 401 and d15["error"] == "invalid_token", f"revoke={st14}, after={st15}")

            for _ in range(5):
                https_req(
                    port, ctx_ok, "POST", "/oauth/token",
                    {"Authorization": basic_hdr("auditor-demo", "bad-secret"), "Content-Type": "application/x-www-form-urlencoded"},
                    form_cc,
                )
            st16, h16, d16 = https_req(
                port, ctx_ok, "POST", "/oauth/token",
                {"Authorization": basic_hdr("auditor-demo", auditor_sec), "Content-Type": "application/x-www-form-urlencoded"},
                form_cc,
            )
            check(15, "Brute-force: 5 невдач -> 429 навіть із вірним секретом", st16 == 429 and "Retry-After" in h16, f"HTTP {st16} Retry-After={h16.get('Retry-After')}s")

            joined_logs = "\n".join(state.audit_log)
            clean_logs = all(s not in joined_logs for s in (gm_sec, player_sec, auditor_sec, gm_token, player_token))
            check(16, "Audit log: без секретів і сирих токенів (лише fp)", clean_logs, f"записів={len(state.audit_log)}, витоків=0")

            print(f"\ngm_hub selftest: {passed}/{total} OK")
            print("--- Останні записи журналу аудиту ---")
            for line in state.audit_log[-6:]:
                print(" ", line)
        finally:
            srv.shutdown()
            srv.server_close()


if __name__ == "__main__":
    run_selftest()