import base64
import copy
import http.client
import json
import os
import secrets
import shutil
import ssl
import tempfile
import threading
import time
from urllib.parse import urlencode

from cryptography.exceptions import InvalidTag

from gm_hub_e2ee import decrypt_session_payload, encrypt_session_payload, generate_recipient_keypair
from gm_hub_logging import verify_security_chain
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
    print("TaleSpire GM Hub 1.2.0 — комплексна самоперевірка (ЛР10-11 + ЛР12 + ЛР13-14)")
    with tempfile.TemporaryDirectory() as tmp:
        ca_cert = os.path.join(tmp, "ca_cert.pem")
        srv_cert = os.path.join(tmp, "srv_cert.pem")
        srv_key = os.path.join(tmp, "srv_key.pem")
        log_dir = os.path.join(tmp, "logs")
        ca_fp = generate_ca_and_server_certs(ca_cert, srv_cert, srv_key)

        bad_ca = os.path.join(tmp, "bad_ca.pem")
        generate_ca_and_server_certs(bad_ca, os.path.join(tmp, "b1.pem"), os.path.join(tmp, "b2.pem"))

        # Ключ отримувача X25519 (закритий лише у ГМ, на сервер реєструється лише відкритий kid)
        gm_priv_x25519, gm_pub_b64, gm_kid = generate_recipient_keypair()
        wrong_priv_x25519, _, _ = generate_recipient_keypair()

        state = HubState(log_dir=log_dir, token_ttl=600, max_failures=5, lock_seconds=300)
        state.register_recipient_kid(gm_kid)
        gm_sec = state.add_client("oleksii-gm", "gm_admin")
        player_sec = state.add_client("player-demo", "player_tester")
        auditor_sec = state.add_client("auditor-demo", "auditor")

        srv = start_https_server(state, srv_cert, srv_key, port=0)
        port = srv.server_address[1]
        threading.Thread(target=srv.serve_forever, daemon=True).start()

        ctx_ok = ssl.create_default_context(cafile=ca_cert)
        ctx_bad = ssl.create_default_context(cafile=bad_ca)

        passed = 0
        total = 28

        def check(num: int, title: str, cond: bool, detail: str) -> None:
            nonlocal passed
            assert cond, f"FAILED {num}: {title} ({detail})"
            passed += 1
            print(f"{num:2d}. OK  {title:<57} | {detail}")

        try:
            st, _, _ = https_req(port, ctx_ok, "GET", "/api/v1/health")
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
            gm_tok_req_id = h5.get("X-Request-ID", "")
            only_hash = gm_token not in state.tokens and sha256_hex(gm_token) in state.tokens
            check(8, "Token: Bearer 600s, no-store, у БД лише SHA-256", st5 == 200 and only_hash and h5.get("Cache-Control") == "no-store", f"HTTP 200, fp={sha256_hex(gm_token)[:12]}")

            _, _, d_aud = https_req(
                port, ctx_ok, "POST", "/oauth/token",
                {"Authorization": basic_hdr("auditor-demo", auditor_sec), "Content-Type": "application/x-www-form-urlencoded"},
                form_cc,
            )
            auditor_token = d_aud["access_token"]

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
            st12, _, _ = https_req(
                port, ctx_ok, "POST", "/api/v1/releases",
                {"Authorization": f"Bearer {gm_token}", "Content-Type": "application/json"},
                spoof_body,
            )
            st13, _, _ = https_req(
                port, ctx_ok, "POST", "/api/v1/releases",
                {"Authorization": f"Bearer {gm_token}", "Content-Type": "application/json"},
                rel_body,
            )
            check(13, "Releases: 201 OK + квитанція, підміна 400, дубль 409", st11 == 201 and "receipt" in d11 and st12 == 400 and st13 == 409, f"block={d11['receipt']['idx']}, spoof={st12}, dup={st13}")

            st14, _, _ = https_req(port, ctx_ok, "POST", "/oauth/revoke", {"Authorization": f"Bearer {player_token}"})
            st15, _, d15 = https_req(port, ctx_ok, "GET", "/api/v1/whoami", {"Authorization": f"Bearer {player_token}"})
            check(14, "Revoke: відкликаний токен (RFC 7009) -> 401", st14 == 200 and st15 == 401 and d15["error"] == "invalid_token", f"revoke={st14}, after={st15}")

            for _ in range(5):
                https_req(
                    port, ctx_ok, "POST", "/oauth/token",
                    {"Authorization": basic_hdr("auditor-demo", "bad-secret"), "Content-Type": "application/x-www-form-urlencoded"},
                    form_cc,
                )
            st16, h16, _ = https_req(
                port, ctx_ok, "POST", "/oauth/token",
                {"Authorization": basic_hdr("auditor-demo", auditor_sec), "Content-Type": "application/x-www-form-urlencoded"},
                form_cc,
            )
            check(15, "Brute-force: 5 невдач -> 429 навіть із вірним секретом", st16 == 429 and "Retry-After" in h16, f"HTTP {st16} Retry-After={h16.get('Retry-After')}s")

            # --- ЛР12 ---
            linked = [e for e in state.logger.memory_general if e.get("request_id") == gm_tok_req_id]
            linked_events = {e["event"] for e in linked}
            ts_utc = all(e["ts"].endswith("Z") for e in linked)
            check(
                16,
                "ЛР12 Лог: JSONL UTC + кореляція X-Request-ID",
                ts_utc and {"auth.token_issued", "http.access"}.issubset(linked_events),
                f"req_id={gm_tok_req_id}, events={sorted(linked_events)}",
            )

            _, _, d_pl2 = https_req(
                port, ctx_ok, "POST", "/oauth/token",
                {"Authorization": basic_hdr("player-demo", player_sec), "Content-Type": "application/x-www-form-urlencoded"},
                form_cc,
            )
            player_token2 = d_pl2["access_token"]
            st_m1, _, _ = https_req(port, ctx_ok, "GET", "/api/v1/metrics", {"Authorization": f"Bearer {player_token2}"})
            st_m2, _, m_data = https_req(port, ctx_ok, "GET", "/api/v1/metrics", {"Authorization": f"Bearer {auditor_token}"})
            check(
                17,
                "ЛР12 Метрики: /api/v1/metrics (player 403 / auditor 200)",
                st_m1 == 403 and st_m2 == 200 and m_data.get("total_requests", 0) > 0,
                f"player={st_m1}, auditor={st_m2}, reqs={m_data.get('total_requests')}",
            )

            for _ in range(3):
                https_req(
                    port, ctx_ok, "POST", "/oauth/token",
                    {"Authorization": basic_hdr("scanner-bot", "bad"), "Content-Type": "application/x-www-form-urlencoded"},
                    form_cc,
                )
            for i in range(10):
                https_req(port, ctx_ok, "GET", f"/api/v1/probe_{i}")
            time.sleep(0.1)
            fired_rules = {e["rule"] for e in state.logger.memory_security if e["event"] == "alert.raised"}
            check(
                18,
                "ЛР12 Алерти: lockout, bruteforce_ip, scan_404",
                {"auth.lockout", "auth.bruteforce_ip", "http.scan_404"}.issubset(fired_rules),
                f"rules={sorted(fired_rules)}",
            )

            sec_path = state.logger.security_log_path()
            ok_intact, sec_count, errs_intact = verify_security_chain(sec_path)
            check(19, "ЛР12 Цілісність: ланцюг SHA-256 безпекового журналу", ok_intact and sec_count >= 15 and not errs_intact, f"записів={sec_count}, chain=OK")

            tampered_path = os.path.join(tmp, "tampered_security.jsonl")
            shutil.copyfile(sec_path, tampered_path)
            with open(tampered_path, "r", encoding="utf-8") as f:
                lines = f.readlines()
            rec_mid = json.loads(lines[5])
            rec_mid["ip"] = "198.51.100.99"
            lines[5] = json.dumps(rec_mid, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n"
            with open(tampered_path, "w", encoding="utf-8") as f:
                f.writelines(lines)
            ok_tamp, _, errs_tamp = verify_security_chain(tampered_path)
            check(20, "ЛР12 Tamper: зміна рядка 6 виявляється миттєво", not ok_tamp and any("рядок 6" in e for e in errs_tamp), errs_tamp[0] if errs_tamp else "")

            redacted_rec = state.logger.emit(
                "INFO",
                "selftest.redaction",
                client_secret="super_secret_123",
                detail="Authorization: Bearer gmh_topsecretvalue999",
            )
            check(
                21,
                "ЛР12 Редагування: секрети й Bearer -> [REDACTED]",
                redacted_rec["client_secret"] == "[REDACTED]" and "[REDACTED]" in redacted_rec["detail"],
                f"detail={redacted_rec['detail']}",
            )

            # --- ЛР13-14: E2EE (X25519 + HKDF-SHA256 + AES-256-GCM) та серверний хеш-ланцюг ---
            secret_marker = "SECRET_BOSS_LOOT_CURSED_RING_V10"
            session_id = "sess-" + secrets.token_hex(6)
            plain_report = {
                "campaign": "Dark Fantasy Act III",
                "gm_note": secret_marker,
                "local_path": r"C:\Users\Oleksii\TaleSpire\Logs\session_10.log",
            }
            meta = {"session_id": session_id, "submitter": "player-demo", "created": "2026-11-22T21:00:00Z", "app": "TaleSpire_GM_Logger"}
            envelope = encrypt_session_payload(plain_report, gm_pub_b64, gm_kid, meta)

            # Перевірка криптографії: підміна шифротексту, AAD-метаданих та чужий ключ -> InvalidTag
            tamper_rejects = 0
            env_bad_ct = copy.deepcopy(envelope)
            raw_ct = bytearray(base64.b64decode(env_bad_ct["ct"]))
            raw_ct[0] ^= 0xFF
            env_bad_ct["ct"] = base64.b64encode(bytes(raw_ct)).decode("ascii")
            for bad_env, priv_k in [
                (env_bad_ct, gm_priv_x25519),
                ({**envelope, "meta": {**meta, "submitter": "evil-user"}}, gm_priv_x25519),
                (envelope, wrong_priv_x25519),
            ]:
                try:
                    decrypt_session_payload(bad_env, priv_k)
                except InvalidTag:
                    tamper_rejects += 1
            check(
                22,
                "ЛР13 E2EE: X25519+AES-GCM, підміна ct/AAD/ключа -> відмова",
                decrypt_session_payload(envelope, gm_priv_x25519) == plain_report and tamper_rejects == 3,
                f"kid={gm_kid}, відмов на підробках 3/3",
            )

            # Надсилання зашифрованого звіту на сервер
            st_s1, _, d_s1 = https_req(
                port, ctx_ok, "POST", "/api/v1/sessions",
                {"Authorization": f"Bearer {player_token2}", "Content-Type": "application/json"},
                json.dumps(envelope).encode("utf-8"),
            )
            stored_json = json.dumps(state.sessions[session_id], ensure_ascii=False)
            no_plain_on_srv = secret_marker not in stored_json and "Dark Fantasy" not in stored_json
            check(
                23,
                "ЛР13 Сервер: прийом E2EE -> 201, у БД лише шифротекст",
                st_s1 == 201 and no_plain_on_srv and d_s1["receipt"]["idx"] == 2,
                f"sid={session_id}, block={d_s1['receipt']['idx']}, відкритого тексту=0",
            )

            # Перевірка валідації метаданих (submitter / kid)
            bad_sub_env = encrypt_session_payload(plain_report, gm_pub_b64, gm_kid, {**meta, "session_id": "sess-bad1", "submitter": "oleksii-gm"})
            st_bad_sub, _, d_bs = https_req(
                port, ctx_ok, "POST", "/api/v1/sessions",
                {"Authorization": f"Bearer {player_token2}", "Content-Type": "application/json"},
                json.dumps(bad_sub_env).encode("utf-8"),
            )
            bad_kid_env = encrypt_session_payload(plain_report, gm_pub_b64, "0000000000000000", {**meta, "session_id": "sess-bad2"})
            st_bad_kid, _, d_bk = https_req(
                port, ctx_ok, "POST", "/api/v1/sessions",
                {"Authorization": f"Bearer {player_token2}", "Content-Type": "application/json"},
                json.dumps(bad_kid_env).encode("utf-8"),
            )
            check(
                24,
                "ЛР13 Валідація E2EE: чужий submitter / kid -> 400",
                st_bad_sub == 400 and d_bs["error"] == "submitter_mismatch" and st_bad_kid == 400 and d_bk["error"] == "unknown_recipient_key",
                f"submitter={st_bad_sub}, kid={st_bad_kid}",
            )

            # Доступ до E2EE-звіту та розшифрування на стороні ГМ
            st_aud_s, _, _ = https_req(port, ctx_ok, "GET", f"/api/v1/sessions/{session_id}", {"Authorization": f"Bearer {auditor_token}"})
            st_pl_s, _, _ = https_req(port, ctx_ok, "GET", f"/api/v1/sessions/{session_id}", {"Authorization": f"Bearer {player_token2}"})
            st_gm_s, _, env_from_srv = https_req(port, ctx_ok, "GET", f"/api/v1/sessions/{session_id}", {"Authorization": f"Bearer {gm_token}"})
            decrypted_by_gm = decrypt_session_payload(env_from_srv, gm_priv_x25519)
            check(
                25,
                "ЛР13 Доступ і дешифрування: auditor 403, GM 200 -> текст",
                st_aud_s == 403 and st_pl_s == 200 and st_gm_s == 200 and decrypted_by_gm["gm_note"] == secret_marker,
                f"auditor={st_aud_s}, player={st_pl_s}, GM=200 (AES-GCM OK)",
            )

            # Серверний хеш-ланцюг: права доступу й перевірка цілісності
            st_lp, _, _ = https_req(port, ctx_ok, "GET", "/api/v1/ledger/verify", {"Authorization": f"Bearer {player_token2}"})
            st_la, _, lv_ok = https_req(port, ctx_ok, "GET", "/api/v1/ledger/verify", {"Authorization": f"Bearer {auditor_token}"})
            kinds = [b["kind"] for b in state.ledger.blocks]
            check(
                26,
                "ЛР14 Хеш-ланцюг: player 403, auditor 200 (ланцюг цілий)",
                st_lp == 403 and st_la == 200 and lv_ok["ok"] is True and kinds == ["genesis", "release", "session"],
                f"blocks={lv_ok['blocks']}, head={lv_ok['head']['hash'][:16]}...",
            )

            # Навмисні підміни даних і блока у сховищі -> виявлення через /api/v1/ledger/verify
            orig_rel = copy.deepcopy(state.releases["1.2.1"])
            orig_sess = copy.deepcopy(state.sessions[session_id])
            orig_blk1 = copy.deepcopy(state.ledger.blocks[1])

            state.releases["1.2.1"]["sha256"] = "f" * 64
            _, _, v1 = https_req(port, ctx_ok, "GET", "/api/v1/ledger/verify", {"Authorization": f"Bearer {auditor_token}"})
            state.releases["1.2.1"] = orig_rel

            state.sessions[session_id]["ct"] = "X" + state.sessions[session_id]["ct"][1:]
            _, _, v2 = https_req(port, ctx_ok, "GET", "/api/v1/ledger/verify", {"Authorization": f"Bearer {auditor_token}"})
            state.sessions[session_id] = orig_sess

            state.ledger.blocks[1]["ref"] = "1.2.1-forged"
            _, _, v3 = https_req(port, ctx_ok, "GET", "/api/v1/ledger/verify", {"Authorization": f"Bearer {auditor_token}"})
            state.ledger.blocks[1] = orig_blk1

            state.releases["9.9.9"] = {"product": "Fake", "version": "9.9.9", "tag": "v9.9.9", "sha256": "0" * 64, "published_by": "evil"}
            _, _, v4 = https_req(port, ctx_ok, "GET", "/api/v1/ledger/verify", {"Authorization": f"Bearer {auditor_token}"})
            del state.releases["9.9.9"]

            _, _, v_restored = https_req(port, ctx_ok, "GET", "/api/v1/ledger/verify", {"Authorization": f"Bearer {auditor_token}"})
            all_caught = (not v1["ok"]) and (not v2["ok"]) and (not v3["ok"]) and (not v4["ok"]) and v_restored["ok"]
            check(
                27,
                "ЛР14 Підміни: реліз / шифротекст / блок / обхід -> виявлено",
                all_caught,
                "4/4 атак виявлено; після відновлення -> ok=True",
            )

            gen_text = open(state.logger.general_log_path(), "r", encoding="utf-8").read()
            sec_text = open(sec_path, "r", encoding="utf-8").read()
            all_text = gen_text + sec_text
            secrets_to_check = (gm_sec, player_sec, auditor_sec, gm_token, player_token, auditor_token, player_token2, secret_marker)
            clean_logs = all(s not in all_text for s in secrets_to_check)
            check(
                28,
                "ЛР12-14 Аудит файлів: 0 витоків секретів, токенів і E2EE",
                clean_logs,
                f"general={len(state.logger.memory_general)}, security={len(state.logger.memory_security)}, витоків=0",
            )

            print(f"\ngm_hub selftest: {passed}/{total} OK")
            print(f"Якір голови серверного хеш-ланцюга: idx={lv_ok['head']['idx']} hash={lv_ok['head']['hash']}")
        finally:
            srv.shutdown()
            srv.server_close()


if __name__ == "__main__":
    run_selftest()