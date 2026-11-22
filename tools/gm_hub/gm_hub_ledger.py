import datetime
import hashlib
import json
import threading

ZERO_HASH = "0" * 64


def canonical_json(obj: dict) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def payload_sha256(obj: dict) -> str:
    return hashlib.sha256(canonical_json(obj).encode("utf-8")).hexdigest()


def compute_ledger_hash(block: dict) -> str:
    body = {
        "idx": block["idx"],
        "ts": block["ts"],
        "kind": block["kind"],
        "ref": block["ref"],
        "payload_sha256": block["payload_sha256"],
        "prev_hash": block["prev_hash"],
    }
    return hashlib.sha256(canonical_json(body).encode("utf-8")).hexdigest()


class HubLedger:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.blocks: list[dict] = []
        self._append_unlocked("genesis", "gm-hub", {"service": "TaleSpire GM Hub", "version": "1.2.0"})

    def _append_unlocked(self, kind: str, ref: str, payload_obj: dict) -> dict:
        idx = len(self.blocks)
        prev = ZERO_HASH if idx == 0 else self.blocks[-1]["hash"]
        ts = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        blk = {
            "idx": idx,
            "ts": ts,
            "kind": kind,
            "ref": ref,
            "payload_sha256": payload_sha256(payload_obj),
            "prev_hash": prev,
        }
        blk["hash"] = compute_ledger_hash(blk)
        self.blocks.append(blk)
        return {"idx": blk["idx"], "ts": blk["ts"], "hash": blk["hash"], "payload_sha256": blk["payload_sha256"]}

    def append(self, kind: str, ref: str, payload_obj: dict) -> dict:
        with self._lock:
            return self._append_unlocked(kind, ref, payload_obj)

    def head(self) -> dict:
        with self._lock:
            last = self.blocks[-1]
            return {"idx": last["idx"], "ts": last["ts"], "hash": last["hash"]}

    def verify(self, releases: dict[str, dict], sessions: dict[str, dict]) -> tuple[bool, list[str]]:
        errors: list[str] = []
        seen_releases: set[str] = set()
        seen_sessions: set[str] = set()

        with self._lock:
            for i, blk in enumerate(self.blocks):
                if blk["idx"] != i:
                    errors.append(f"блок {i}: некоректний індекс ({blk['idx']})")
                expected_prev = ZERO_HASH if i == 0 else self.blocks[i - 1]["hash"]
                if blk["prev_hash"] != expected_prev:
                    errors.append(f"блок {i}: prev_hash не збігається з блоком {i - 1} (ланцюг розірвано)")
                calc = compute_ledger_hash(blk)
                if blk["hash"] != calc:
                    errors.append(f"блок {i}: хеш не відповідає вмісту блока (блок змінено)")

                kind = blk["kind"]
                ref = blk["ref"]
                if kind == "release":
                    seen_releases.add(ref)
                    if ref not in releases:
                        errors.append(f"блок {i}: release {ref} відсутній у сховищі")
                    elif payload_sha256(releases[ref]) != blk["payload_sha256"]:
                        errors.append(f"блок {i}: release {ref} змінено після фіксації (SHA-256 не збігається)")
                elif kind == "session":
                    seen_sessions.add(ref)
                    if ref not in sessions:
                        errors.append(f"блок {i}: session {ref} відсутній у сховищі")
                    elif payload_sha256(sessions[ref]) != blk["payload_sha256"]:
                        errors.append(f"блок {i}: session {ref} змінено після фіксації (SHA-256 не збігається)")

            for ver in sorted(releases.keys()):
                if ver not in seen_releases:
                    errors.append(f"release {ver} є у сховищі, але відсутній у хеш-ланцюгу (додано в обхід)")
            for sid in sorted(sessions.keys()):
                if sid not in seen_sessions:
                    errors.append(f"session {sid} є у сховищі, але відсутній у хеш-ланцюгу (додано в обхід)")

        return len(errors) == 0, errors