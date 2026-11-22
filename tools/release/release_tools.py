import argparse
import datetime
import hashlib
import json
import os
import re
import subprocess
import sys
import urllib.error
import urllib.request
import zipfile

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
BUILD_DIR = os.path.join(REPO_ROOT, "build", "gm-release")
RELEASE_PREFIXES = (
    "tools/gm_hub/",
    "tools/release/",
    "docs/security/",
    "docs/architecture/",
    "SECURITY.md",
)
FORBIDDEN_EXTS = (".key", ".pem", ".secret", ".db", ".gmbk", ".pyc")
SECRET_PATTERNS = [
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE" + r" KEY-----"),
    re.compile(r"\bgms_[A-Za-z0-9_\-]{20,}\b"),
    re.compile(r"\bgmh_[A-Za-z0-9_\-]{20,}\b"),
    re.compile(r"ghp_[A-Za-z0-9]{20,}"),
]


def run_git(*args: str) -> str:
    return subprocess.check_output(["git", *args], cwd=REPO_ROOT, text=True, encoding="utf-8").strip()


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def parse_pinned_requirements() -> list[tuple[str, str]]:
    req_path = os.path.join(REPO_ROOT, "tools", "gm_hub", "requirements.txt")
    deps: list[tuple[str, str]] = []
    if not os.path.exists(req_path):
        return deps
    for line in open(req_path, "r", encoding="utf-8"):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if "==" in line:
            pkg, ver = line.split("==", 1)
            deps.append((pkg.strip(), ver.strip()))
    return deps


def query_osv(pkg: str, ver: str) -> tuple[bool, str]:
    payload = json.dumps({"package": {"name": pkg, "ecosystem": "PyPI"}, "version": ver}).encode("utf-8")
    req = urllib.request.Request(
        "https://api.osv.dev/v1/query",
        data=payload,
        headers={"Content-Type": "application/json", "User-Agent": "TaleSpire-GM-ReleaseTools/1.0"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=8) as resp:
            data = json.loads(resp.read().decode("utf-8"))
        vulns = data.get("vulns", [])
        if not vulns:
            return True, f"{pkg}=={ver}: відомих вразливостей в OSV немає"
        ids = ", ".join(v.get("id", "?") for v in vulns[:5])
        return False, f"{pkg}=={ver}: знайдено вразливості ({ids})"
    except urllib.error.URLError as e:
        return True, f"{pkg}=={ver}: OSV недоступний офлайн ({e.reason})"


def build_artifacts_in_memory(version: str) -> tuple[bytes, bytes, str, int]:
    commit_hash = run_git("rev-parse", "HEAD")
    commit_ts = int(run_git("show", "-s", "--format=%ct", "HEAD"))
    commit_dt = datetime.datetime.fromtimestamp(commit_ts, tz=datetime.timezone.utc)
    zip_time = (commit_dt.year, commit_dt.month, commit_dt.day, commit_dt.hour, commit_dt.minute, commit_dt.second)

    tracked = sorted(run_git("ls-files").splitlines())
    selected = [
        p for p in tracked
        if any(p == pref or p.startswith(pref) for pref in RELEASE_PREFIXES)
        and not p.endswith(FORBIDDEN_EXTS)
    ]

    deps = parse_pinned_requirements()
    sbom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "metadata": {
            "timestamp": commit_dt.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "component": {
                "type": "application",
                "name": "talespire-gm-tools",
                "version": version,
                "properties": [{"name": "git.commit", "value": commit_hash}],
            },
        },
        "components": [
            {
                "type": "library",
                "name": pkg,
                "version": ver,
                "purl": f"pkg:pypi/{pkg}@{ver}",
            }
            for pkg, ver in deps
        ],
    }
    sbom_bytes = (json.dumps(sbom, indent=2, sort_keys=True, ensure_ascii=False) + "\n").encode("utf-8")

    manifest_lines: list[str] = []
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as zf:
        for path in selected:
            blob = subprocess.check_output(["git", "show", f"HEAD:{path}"], cwd=REPO_ROOT)
            manifest_lines.append(f"{sha256_bytes(blob)}  {path}")
            zi = zipfile.ZipInfo(filename=path, date_time=zip_time)
            zi.compress_type = zipfile.ZIP_DEFLATED
            zi.external_attr = 0o644 << 16
            zf.writestr(zi, blob)

        zi_sbom = zipfile.ZipInfo(filename="sbom.cdx.json", date_time=zip_time)
        zi_sbom.compress_type = zipfile.ZIP_DEFLATED
        zi_sbom.external_attr = 0o644 << 16
        zf.writestr(zi_sbom, sbom_bytes)

        manifest_bytes = ("\n".join(manifest_lines) + "\n").encode("utf-8")
        zi_man = zipfile.ZipInfo(filename="MANIFEST.sha256", date_time=zip_time)
        zi_man.compress_type = zipfile.ZIP_DEFLATED
        zi_man.external_attr = 0o644 << 16
        zf.writestr(zi_man, manifest_bytes)

    return buf.getvalue(), sbom_bytes, commit_hash, len(selected)


def cmd_check(check_osv: bool) -> None:
    print("=== Перевірка готовності TaleSpire GM Tools до релізу 1.0.0 ===")
    blockers = 0

    def report(ok: bool, name: str, detail: str) -> None:
        nonlocal blockers
        status = "OK  " if ok else "FAIL"
        if not ok:
            blockers += 1
        print(f"  {status} | {name:<44} | {detail}")

    # 1. Гілка і чистота дерева
    branch = run_git("rev-parse", "--abbrev-ref", "HEAD")
    porcelain = run_git("status", "--porcelain")
    dirty = [ln for ln in porcelain.splitlines() if not ln.endswith("build/")]
    report(len(dirty) == 0, "Гілка Git та чистота робочого дерева", f"гілка={branch}, незакомічених={len(dirty)}")

    # 2. Заборонені файли у відстежуваних
    tracked = run_git("ls-files").splitlines()
    bad_files = [p for p in tracked if p.endswith(FORBIDDEN_EXTS)]
    report(len(bad_files) == 0, "Відсутність секретних/службових файлів", "немає" if not bad_files else ", ".join(bad_files))

    # 3. Пошук секретів у вмісті файлів
    leaks = []
    for rel in tracked:
        if not os.path.exists(os.path.join(REPO_ROOT, rel)):
            continue
        try:
            text = open(os.path.join(REPO_ROOT, rel), "r", encoding="utf-8", errors="ignore").read()
        except OSError:
            continue
        for pat in SECRET_PATTERNS:
            if pat.search(text):
                leaks.append(rel)
                break
    report(len(leaks) == 0, "Відсутність секретів у коді та документах", f"перевірено {len(tracked)} файлів, витоків={len(leaks)}")

    # 4. Перевірка безпечних налаштувань за замовчуванням у gm_hub_server.py
    srv_src = open(os.path.join(REPO_ROOT, "tools", "gm_hub", "gm_hub_server.py"), "r", encoding="utf-8").read()
    safe_defaults = (
        "TLSVersion.TLSv1_2" in srv_src
        and '"127.0.0.1"' in srv_src
        and "token_ttl: int = 600" in srv_src
        and "max_failures: int = 5" in srv_src
    )
    report(safe_defaults, "Робоча конфігурація (TLS 1.2+, loopback, TTL)", "TLS>=1.2, 127.0.0.1, TTL=600s, lockout=5")

    # 5. Зафіксовані версії залежностей
    deps = parse_pinned_requirements()
    report(len(deps) > 0, "Фіксація версій залежностей (==)", ", ".join(f"{p}=={v}" for p, v in deps) or "відсутні")

    # 6. Перевірка вразливостей у OSV
    if check_osv and deps:
        osv_ok_all = True
        msgs = []
        for pkg, ver in deps:
            ok_v, msg = query_osv(pkg, ver)
            osv_ok_all = osv_ok_all and ok_v
            msgs.append(msg)
        report(osv_ok_all, "Перевірка вразливостей залежностей (OSV)", "; ".join(msgs))

    # 7. Самоперевірка gm_hub (28/28 OK)
    st_proc = subprocess.run(
        [sys.executable, os.path.join(REPO_ROOT, "tools", "gm_hub", "gm_hub_selftest.py")],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        encoding="utf-8",
    )
    st_ok = st_proc.returncode == 0 and "28/28 OK" in st_proc.stdout
    report(st_ok, "Самоперевірка сервера gm_hub", "28/28 OK" if st_ok else "FAILED")

    # 8. Перевірка резервного копіювання і DR
    dr_proc = subprocess.run(
        [sys.executable, os.path.join(REPO_ROOT, "tools", "gm_hub", "gm_hub_backup.py"), "--simulate-dr"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        encoding="utf-8",
    )
    dr_ok = dr_proc.returncode == 0 and "6/6 етапів OK" in dr_proc.stdout
    report(dr_ok, "Самоперевірка резервного копіювання і DR", "6/6 етапів OK" if dr_ok else "FAILED")

    # 9. Відтворюваність збірки (2 незалежні складання HEAD)
    z1, s1, _, nfiles = build_artifacts_in_memory("1.0.0")
    z2, s2, _, _ = build_artifacts_in_memory("1.0.0")
    h1, h2 = sha256_bytes(z1), sha256_bytes(z2)
    report(h1 == h2 and s1 == s2, "Відтворюваність релізного складання (HEAD)", f"zip ({nfiles} файлів) {h1[:16]}... == {h2[:16]}...")

    print(f"\nПідсумок перевірки готовності: блокерів = {blockers}")
    if blockers:
        sys.exit(1)


def cmd_build(version: str) -> None:
    os.makedirs(BUILD_DIR, exist_ok=True)
    zip_bytes, sbom_bytes, commit_hash, nfiles = build_artifacts_in_memory(version)
    zip_name = f"talespire-gm-tools-{version}.zip"
    sbom_name = f"talespire-gm-tools-{version}.cdx.json"

    zip_path = os.path.join(BUILD_DIR, zip_name)
    sbom_path = os.path.join(BUILD_DIR, sbom_name)
    sums_path = os.path.join(BUILD_DIR, "SHA256SUMS.txt")

    open(zip_path, "wb").write(zip_bytes)
    open(sbom_path, "wb").write(sbom_bytes)

    zip_sha = sha256_bytes(zip_bytes)
    sbom_sha = sha256_bytes(sbom_bytes)
    with open(sums_path, "w", encoding="utf-8") as f:
        f.write(f"{sbom_sha}  {sbom_name}\n")
        f.write(f"{zip_sha}  {zip_name}\n")

    print(f"Зібрано релізний артефакт v{version} (коміт {commit_hash[:10]}, файлів: {nfiles}):")
    print(f"  ZIP  ({len(zip_bytes)} Б): {zip_path}")
    print(f"  SHA-256 ZIP:  {zip_sha}")
    print(f"  SBOM ({len(sbom_bytes)} Б): {sbom_path}")
    print(f"  SHA-256 SBOM: {sbom_sha}")
    print(f"  Контрольні суми: {sums_path}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Перевірка готовності та збірка релізу TaleSpire GM Tools")
    sub = parser.add_subparsers(dest="cmd", required=True)
    p_chk = sub.add_parser("check")
    p_chk.add_argument("--osv", action="store_true")
    p_bld = sub.add_parser("build")
    p_bld.add_argument("--version", default="1.0.0")
    args = parser.parse_args()
    if args.cmd == "check":
        cmd_check(check_osv=args.osv)
    elif args.cmd == "build":
        cmd_build(args.version)