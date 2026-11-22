import argparse
import datetime
import hashlib
import io
import json
import os
import secrets
import shutil
import tempfile
import time
import zipfile

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

from gm_hub_e2ee import encrypt_session_payload, generate_recipient_keypair
from gm_hub_ledger import HubLedger
from gm_hub_server import generate_ca_and_server_certs

MAGIC = b"GMBK1"
SCRYPT_N = 2**15
SCRYPT_R = 8
SCRYPT_P = 1


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def derive_key(passphrase: str, salt: bytes) -> bytes:
    kdf = Scrypt(salt=salt, length=32, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P)
    return kdf.derive(passphrase.encode("utf-8"))


def create_backup(data_dir: str, dest_dir: str, passphrase: str, label: str = "daily") -> tuple[str, dict]:
    if len(passphrase) < 12:
        raise ValueError("Парольна фраза має містити щонайменше 12 символів")
    os.makedirs(dest_dir, exist_ok=True)

    ts_tag = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%d-%H%M%S")
    created_iso = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    archive_name = f"gm-hub-{ts_tag}-{label}.gmbk"
    archive_path = os.path.join(dest_dir, archive_name)

    files_to_pack: list[tuple[str, bytes]] = []
    for root, _, filenames in os.walk(data_dir):
        for fname in sorted(filenames):
            full = os.path.join(root, fname)
            rel = os.path.relpath(full, data_dir).replace("\\", "/")
            # Пропускаємо кеші, загальні логи низької цінності та тимчасові файли
            if rel.startswith("logs/gm_hub-") or rel.endswith(".tmp") or "__pycache__" in rel:
                continue
            raw = open(full, "rb").read()
            # Очищаємо сеансовий стан (токени, лічильники невдач) перед резервуванням
            if rel == "state.json":
                st_obj = json.loads(raw.decode("utf-8"))
                st_obj["tokens"] = {}
                st_obj["failures"] = {}
                raw = json.dumps(st_obj, indent=2, sort_keys=True, ensure_ascii=False).encode("utf-8")
            files_to_pack.append((rel, raw))

    files_to_pack.sort(key=lambda x: x[0])
    manifest = {
        "format": "gm-hub-backup-v1",
        "created": created_iso,
        "label": label,
        "files": {rel: {"size": len(raw), "sha256": sha256_bytes(raw)} for rel, raw in files_to_pack},
    }

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("manifest.json", json.dumps(manifest, indent=2, sort_keys=True, ensure_ascii=False))
        for rel, raw in files_to_pack:
            zf.writestr(f"payload/{rel}", raw)

    salt = os.urandom(16)
    nonce = os.urandom(12)
    key = derive_key(passphrase, salt)
    aad = archive_name.encode("utf-8")
    ct = AESGCM(key).encrypt(nonce, buf.getvalue(), aad)
    blob = MAGIC + salt + nonce + ct

    with open(archive_path, "wb") as f:
        f.write(blob)

    arch_sha = sha256_bytes(blob)
    sha_path = archive_path + ".sha256"
    with open(sha_path, "w", encoding="utf-8") as f:
        f.write(f"{arch_sha}  {archive_name}\n")

    return archive_path, {
        "archive": archive_name,
        "size_bytes": len(blob),
        "files_count": len(files_to_pack),
        "sha256": arch_sha,
        "created": created_iso,
    }


def _decrypt_zip(archive_path: str, passphrase: str) -> bytes:
    blob = open(archive_path, "rb").read()
    if not blob.startswith(MAGIC) or len(blob) < len(MAGIC) + 28:
        raise ValueError("Некоректний формат архіву резервної копії")
    salt = blob[len(MAGIC):len(MAGIC) + 16]
    nonce = blob[len(MAGIC) + 16:len(MAGIC) + 28]
    ct = blob[len(MAGIC) + 28:]
    key = derive_key(passphrase, salt)
    aad = os.path.basename(archive_path).encode("utf-8")
    return AESGCM(key).decrypt(nonce, ct, aad)


def verify_backup(archive_path: str, passphrase: str | None = None, deep: bool = False) -> dict:
    problems: list[str] = []
    sha_path = archive_path + ".sha256"
    actual_sha = sha256_file(archive_path)
    sha_ok = False
    if os.path.exists(sha_path):
        expected_sha = open(sha_path, "r", encoding="utf-8").read().strip().split()[0]
        sha_ok = (actual_sha == expected_sha)
        if not sha_ok:
            problems.append("SHA-256 архіву не збігається з .sha256 (файл пошкоджено або змінено)")
    else:
        problems.append("Відсутній супровідний файл .sha256")

    result = {
        "archive": os.path.basename(archive_path),
        "sha256_ok": sha_ok,
        "deep": deep,
        "ok": sha_ok and not problems,
        "problems": problems,
    }
    if not deep:
        return result

    if not passphrase:
        problems.append("Для глибокої перевірки (--deep) потрібна парольна фраза")
        result["ok"] = False
        return result

    try:
        zip_bytes = _decrypt_zip(archive_path, passphrase)
    except InvalidTag:
        problems.append("Автентифікацію AES-GCM не пройдено: невірна фраза або архів пошкоджено")
        result["ok"] = False
        return result

    with zipfile.ZipFile(io.BytesIO(zip_bytes), "r") as zf:
        manifest = json.loads(zf.read("manifest.json").decode("utf-8"))
        for rel, meta in manifest["files"].items():
            member = f"payload/{rel}"
            if member not in zf.namelist():
                problems.append(f"Відсутній файл у маніфесті: {rel}")
                continue
            raw = zf.read(member)
            if sha256_bytes(raw) != meta["sha256"]:
                problems.append(f"Пошкоджено файл у копії: {rel}")

        # Перевіряємо цілісність хеш-ланцюга всередині резервної копії
        if "payload/state.json" in zf.namelist() and "payload/ledger.json" in zf.namelist():
            st_obj = json.loads(zf.read("payload/state.json").decode("utf-8"))
            ld_obj = json.loads(zf.read("payload/ledger.json").decode("utf-8"))
            ledger = HubLedger()
            ledger.blocks = ld_obj["blocks"]
            l_ok, l_errs = ledger.verify(st_obj.get("releases", {}), st_obj.get("sessions", {}))
            result["ledger_ok"] = l_ok
            result["ledger_head"] = ledger.head()
            result["counts"] = {
                "clients": len(st_obj.get("clients", {})),
                "releases": len(st_obj.get("releases", {})),
                "sessions": len(st_obj.get("sessions", {})),
                "tokens_cleared": len(st_obj.get("tokens", {})),
                "ledger_blocks": len(ledger.blocks),
            }
            if not l_ok:
                problems.extend(l_errs)

    result["manifest_files"] = len(manifest["files"])
    result["ok"] = len(problems) == 0
    return result


def restore_backup(archive_path: str, target_dir: str, passphrase: str) -> dict:
    t0 = time.perf_counter()
    v = verify_backup(archive_path, passphrase=passphrase, deep=True)
    if not v["ok"]:
        raise RuntimeError(f"Відновлення скасовано: {v['problems']}")

    if os.path.exists(os.path.join(target_dir, "server.lock")):
        raise RuntimeError("У цільовій теці працює активний сервер (server.lock) — спершу зупиніть його")

    os.makedirs(target_dir, exist_ok=True)
    zip_bytes = _decrypt_zip(archive_path, passphrase)
    restored = 0
    with zipfile.ZipFile(io.BytesIO(zip_bytes), "r") as zf:
        manifest = json.loads(zf.read("manifest.json").decode("utf-8"))
        for rel in manifest["files"]:
            dest_path = os.path.normpath(os.path.join(target_dir, rel))
            if not dest_path.startswith(os.path.abspath(target_dir)):
                raise RuntimeError(f"Небезпечний шлях у резервній копії: {rel}")
            os.makedirs(os.path.dirname(dest_path), exist_ok=True)
            with open(dest_path, "wb") as out:
                out.write(zf.read(f"payload/{rel}"))
            restored += 1

    return {
        "target": target_dir,
        "restored_files": restored,
        "ledger_ok": v.get("ledger_ok", True),
        "ledger_head": v.get("ledger_head"),
        "counts": v.get("counts"),
        "restore_seconds": round(time.perf_counter() - t0, 3),
    }


def simulate_disaster_recovery() -> None:
    print("=== TaleSpire GM Hub — резервне копіювання, верифікація та аварійне відновлення (ЛР15-16) ===")
    passphrase = "Lab15-16-DR-StrongPassphrase-V10!"
    with tempfile.TemporaryDirectory() as tmp:
        work_dir = os.path.join(tmp, "gm_hub_data")
        backup_dir = os.path.join(tmp, "GM_backups")
        os.makedirs(os.path.join(work_dir, "tls"), exist_ok=True)
        os.makedirs(os.path.join(work_dir, "logs"), exist_ok=True)
        os.makedirs(os.path.join(work_dir, "keys"), exist_ok=True)

        # 1. Формуємо робочий стан сервера (TLS, клієнти, реліз, E2EE-звіт, хеш-ланцюг, ключ E2EE)
        generate_ca_and_server_certs(
            os.path.join(work_dir, "tls", "ca_cert.pem"),
            os.path.join(work_dir, "tls", "srv_cert.pem"),
            os.path.join(work_dir, "tls", "srv_key.pem"),
        )
        _, gm_pub_b64, gm_kid = generate_recipient_keypair()
        with open(os.path.join(work_dir, "keys", "gm_recipient_kid.txt"), "w", encoding="utf-8") as f:
            f.write(gm_kid)
        with open(os.path.join(work_dir, "logs", "gm_security-2026-11-22.jsonl"), "w", encoding="utf-8") as f:
            f.write('{"event":"server.initialized","level":"INFO","ts":"2026-11-22T21:30:00.000Z"}\n')

        rel_rec = {
            "product": "TaleSpire_GM_Logger_Pro",
            "version": "1.0.0",
            "tag": "gm-tools-v1.0.0",
            "sha256": "a" * 64,
            "published_by": "oleksii-gm",
        }
        sess_meta = {"session_id": "sess-dr-001", "submitter": "player-demo", "created": "2026-11-22T21:35:00Z", "app": "TaleSpire_GM_Logger"}
        sess_env = encrypt_session_payload({"note": "Campaign backup check"}, gm_pub_b64, gm_kid, sess_meta)

        ledger = HubLedger()
        ledger.append("release", "1.0.0", rel_rec)
        ledger.append("session", "sess-dr-001", sess_env)
        anchor_before = ledger.head()

        state_obj = {
            "clients": {"oleksii-gm": {"role": "gm_admin"}, "player-demo": {"role": "player_tester"}, "auditor-demo": {"role": "auditor"}},
            "releases": {"1.0.0": rel_rec},
            "sessions": {"sess-dr-001": sess_env},
            "tokens": {"active_token_hash_should_not_be_backed_up": {"client_id": "oleksii-gm"}},
            "failures": {"intruder": {"count": 4}},
        }
        with open(os.path.join(work_dir, "state.json"), "w", encoding="utf-8") as f:
            json.dump(state_obj, f, indent=2)
        with open(os.path.join(work_dir, "ledger.json"), "w", encoding="utf-8") as f:
            json.dump({"blocks": ledger.blocks}, f, indent=2)

        # 2. Створення зашифрованої резервної копії
        t_b0 = time.perf_counter()
        arc_path, meta = create_backup(work_dir, backup_dir, passphrase, label="lab15")
        print(f"\n[1. CREATE] Створено {meta['archive']} ({meta['size_bytes']} Б, файлів: {meta['files_count']}) за {time.perf_counter() - t_b0:.2f} с")
        print(f"  SHA-256: {meta['sha256']}")

        # 3. Перевірка цілісності (швидка та глибока --deep)
        v_fast = verify_backup(arc_path, deep=False)
        v_deep = verify_backup(arc_path, passphrase=passphrase, deep=True)
        print(f"\n[2. VERIFY] Швидка (.sha256): ok={v_fast['ok']} | Глибока (AES-GCM + маніфест + хеш-ланцюг): ok={v_deep['ok']}")
        print(f"  Склад у копії: {v_deep['counts']} | Голова ланцюга: idx={v_deep['ledger_head']['idx']} hash={v_deep['ledger_head']['hash'][:24]}...")

        # 4. Негативні перевірки копії (підміна байта та невірна парольна фраза)
        bad_copy = os.path.join(tmp, "corrupted.gmbk")
        shutil.copyfile(arc_path, bad_copy)
        shutil.copyfile(arc_path + ".sha256", bad_copy + ".sha256")
        raw_bad = bytearray(open(bad_copy, "rb").read())
        raw_bad[-10] ^= 0xFF
        open(bad_copy, "wb").write(raw_bad)
        v_tamper = verify_backup(bad_copy, passphrase=passphrase, deep=True)
        v_wrong_pw = verify_backup(arc_path, passphrase="Wrong-Passphrase-12345", deep=True)
        print(f"\n[3. TAMPER & AUTH] Зміна 1 байта -> ok={v_tamper['ok']} ({v_tamper['problems'][0]})")
        print(f"  Невірна парольна фраза -> ok={v_wrong_pw['ok']} ({v_wrong_pw['problems'][0]})")

        # 5. Моделювання повної втрати робочих даних
        t_dr0 = time.perf_counter()
        shutil.rmtree(work_dir)
        state_exists = os.path.exists(os.path.join(work_dir, "state.json"))
        print(f"\n[4. DISASTER] Робочу теку gm_hub_data знищено! Наявність state.json: {state_exists} (сервер не може стартувати)")

        # 6. Аварійне відновлення з резервної копії та перевірка працездатності
        res = restore_backup(arc_path, work_dir, passphrase)
        restored_state = json.loads(open(os.path.join(work_dir, "state.json"), "r", encoding="utf-8").read())
        restored_ledger_raw = json.loads(open(os.path.join(work_dir, "ledger.json"), "r", encoding="utf-8").read())
        r_ledger = HubLedger()
        r_ledger.blocks = restored_ledger_raw["blocks"]
        r_ok, r_errs = r_ledger.verify(restored_state["releases"], restored_state["sessions"])
        anchor_match = (r_ledger.head()["hash"] == anchor_before["hash"])
        actual_rto = round(time.perf_counter() - t_dr0, 3)

        print(f"\n[5. RESTORE] Відновлено {res['restored_files']} файлів за {res['restore_seconds']} с (фактичний RTO: {actual_rto} с при нормі <= 3600 с)")
        print(f"  Перевірка після відновлення: ledger_ok={r_ok}, збіг голови з якорем={anchor_match}, очищено сеансових токенів={len(restored_state['tokens']) == 0}")
        assert v_fast["ok"] and v_deep["ok"] and (not v_tamper["ok"]) and (not v_wrong_pw["ok"])
        assert r_ok and anchor_match and len(restored_state["tokens"]) == 0 and not r_errs
        print("\nDR-симуляція та перевірка резервних копій: УСПІШНО (6/6 етапів OK)")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Резервне копіювання та відновлення TaleSpire GM Hub")
    parser.add_argument("--simulate-dr", action="store_true", help="Запустити повну симуляцію копіювання, втрати й відновлення")
    args = parser.parse_args()
    if args.simulate_dr:
        simulate_disaster_recovery()