import datetime
import hashlib
import json
import os
import re
import threading
import time
from collections import deque

SENSITIVE_KEYS = {
    "password",
    "secret",
    "client_secret",
    "access_token",
    "refresh_token",
    "token",
    "authorization",
    "private_key",
}

BEARER_BASIC_RE = re.compile(r"\b(Bearer|Basic)\s+[A-Za-z0-9._\-+/=]+", re.IGNORECASE)
TOKEN_PREFIX_RE = re.compile(r"\b(?:gmh|gms)_[A-Za-z0-9_\-]{8,}\b")
ZERO_HASH = "0" * 64


def utc_now_iso() -> str:
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def utc_date_str() -> str:
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d")


def redact_text(value: str) -> str:
    masked = BEARER_BASIC_RE.sub(r"\1 [REDACTED]", value)
    masked = TOKEN_PREFIX_RE.sub("[REDACTED]", masked)
    return masked


def redact_value(key: str | None, value):
    if key and key.lower() in SENSITIVE_KEYS:
        return "[REDACTED]"
    if isinstance(value, str):
        return redact_text(value)
    if isinstance(value, dict):
        return {k: redact_value(str(k), v) for k, v in value.items()}
    if isinstance(value, list):
        return [redact_value(None, item) for item in value]
    return value


class HubMetrics:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.started_at = time.time()
        self.total_requests = 0
        self.status_counts: dict[str, int] = {}
        self.route_counts: dict[str, int] = {}
        self.latencies_ms: deque[float] = deque(maxlen=500)
        self._req_window: deque[float] = deque()
        self._err5xx_window: deque[float] = deque()
        self._auth_fail_ip: dict[str, deque[float]] = {}
        self._scan_404_ip: dict[str, deque[float]] = {}
        self._forbid_403_window: deque[float] = deque()
        self._alert_fired: dict[tuple[str, str], float] = {}
        self.alerts_total = 0

    def _prune(self, dq: deque[float], now: float, window_s: float) -> None:
        cutoff = now - window_s
        while dq and dq[0] < cutoff:
            dq.popleft()

    def _should_alert(self, rule: str, subject: str, now: float, cooldown_s: float = 30.0) -> bool:
        key = (rule, subject)
        last = self._alert_fired.get(key, 0.0)
        if now - last >= cooldown_s:
            self._alert_fired[key] = now
            self.alerts_total += 1
            return True
        return False

    def record_http(self, route: str, status: int, ip: str, duration_ms: float) -> list[dict]:
        now = time.time()
        alerts: list[dict] = []
        with self._lock:
            self.total_requests += 1
            st_key = str(status)
            self.status_counts[st_key] = self.status_counts.get(st_key, 0) + 1
            self.route_counts[route] = self.route_counts.get(route, 0) + 1
            self.latencies_ms.append(round(duration_ms, 2))
            self._req_window.append(now)
            self._prune(self._req_window, now, 300.0)

            if status == 404:
                dq = self._scan_404_ip.setdefault(ip, deque())
                dq.append(now)
                self._prune(dq, now, 60.0)
                if len(dq) >= 10 and self._should_alert("http.scan_404", ip, now):
                    alerts.append({"rule": "http.scan_404", "subject": ip, "count": len(dq), "window_s": 60})

            if status == 403:
                self._forbid_403_window.append(now)
                self._prune(self._forbid_403_window, now, 60.0)
                if len(self._forbid_403_window) >= 5 and self._should_alert("authz.forbidden_spike", ip, now):
                    alerts.append({
                        "rule": "authz.forbidden_spike",
                        "subject": ip,
                        "count": len(self._forbid_403_window),
                        "window_s": 60,
                    })

            if status >= 500:
                self._err5xx_window.append(now)
                self._prune(self._err5xx_window, now, 60.0)
                if len(self._err5xx_window) >= 3 and self._should_alert("http.server_error_spike", "server", now):
                    alerts.append({
                        "rule": "http.server_error_spike",
                        "subject": "server",
                        "count": len(self._err5xx_window),
                        "window_s": 60,
                    })
        return alerts

    def record_auth_failure(self, ip: str, client_id: str, locked: bool) -> list[dict]:
        now = time.time()
        alerts: list[dict] = []
        with self._lock:
            dq = self._auth_fail_ip.setdefault(ip, deque())
            dq.append(now)
            self._prune(dq, now, 60.0)
            if locked and self._should_alert("auth.lockout", client_id, now, cooldown_s=5.0):
                alerts.append({"rule": "auth.lockout", "subject": client_id, "count": 1, "window_s": 0})
            if len(dq) >= 8 and self._should_alert("auth.bruteforce_ip", ip, now):
                alerts.append({"rule": "auth.bruteforce_ip", "subject": ip, "count": len(dq), "window_s": 60})
        return alerts

    def snapshot(self) -> dict:
        now = time.time()
        with self._lock:
            self._prune(self._req_window, now, 300.0)
            self._prune(self._err5xx_window, now, 60.0)
            auth_fail_5m = 0
            for dq in self._auth_fail_ip.values():
                self._prune(dq, now, 300.0)
                auth_fail_5m += len(dq)
            sorted_lat = sorted(self.latencies_ms)
            p50 = sorted_lat[len(sorted_lat) // 2] if sorted_lat else 0.0
            p95 = sorted_lat[min(len(sorted_lat) - 1, int(len(sorted_lat) * 0.95))] if sorted_lat else 0.0
            return {
                "uptime_s": round(now - self.started_at, 1),
                "total_requests": self.total_requests,
                "requests_5m": len(self._req_window),
                "auth_failures_5m": auth_fail_5m,
                "errors_5xx_1m": len(self._err5xx_window),
                "alerts_total": self.alerts_total,
                "latency_ms": {"p50": p50, "p95": p95},
                "status_counts": dict(self.status_counts),
                "route_counts": dict(self.route_counts),
            }


class HubLogger:
    def __init__(self, log_dir: str | None = None, version: str = "1.1.0") -> None:
        self.log_dir = log_dir
        self.version = version
        self._lock = threading.Lock()
        self._last_sec_hash = ZERO_HASH
        self.memory_general: list[dict] = []
        self.memory_security: list[dict] = []
        if self.log_dir:
            os.makedirs(self.log_dir, exist_ok=True)
            self._sync_chain_tail()

    def general_log_path(self) -> str | None:
        if not self.log_dir:
            return None
        return os.path.join(self.log_dir, f"gm_hub-{utc_date_str()}.jsonl")

    def security_log_path(self) -> str | None:
        if not self.log_dir:
            return None
        return os.path.join(self.log_dir, f"gm_security-{utc_date_str()}.jsonl")

    def _sync_chain_tail(self) -> None:
        sec_path = self.security_log_path()
        if sec_path and os.path.exists(sec_path):
            last_line = ""
            with open(sec_path, "r", encoding="utf-8") as f:
                for line in f:
                    if line.strip():
                        last_line = line.strip()
            if last_line:
                self._last_sec_hash = json.loads(last_line).get("entry_hash", ZERO_HASH)

    def emit(
        self,
        level: str,
        event: str,
        *,
        security: bool = False,
        request_id: str | None = None,
        ip: str | None = None,
        client_id: str | None = None,
        token_fp: str | None = None,
        **fields,
    ) -> dict:
        record = {
            "ts": utc_now_iso(),
            "level": level.upper(),
            "event": event,
            "component": "gm_hub",
            "version": self.version,
            "pid": os.getpid(),
        }
        if request_id:
            record["request_id"] = request_id
        if ip:
            record["ip"] = ip
        if client_id:
            record["client_id"] = client_id
        if token_fp:
            record["token_fp"] = token_fp
        for k, v in fields.items():
            if v is not None:
                record[k] = redact_value(k, v)

        with self._lock:
            gen_line = json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
            self.memory_general.append(dict(record))
            gen_path = self.general_log_path()
            if gen_path:
                with open(gen_path, "a", encoding="utf-8") as f:
                    f.write(gen_line + "\n")

            if security:
                sec_rec = dict(record)
                sec_rec["prev_hash"] = self._last_sec_hash
                canonical = json.dumps(sec_rec, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
                entry_hash = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
                sec_rec["entry_hash"] = entry_hash
                self._last_sec_hash = entry_hash
                self.memory_security.append(sec_rec)
                sec_path = self.security_log_path()
                if sec_path:
                    sec_line = json.dumps(sec_rec, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
                    with open(sec_path, "a", encoding="utf-8") as f:
                        f.write(sec_line + "\n")
                return sec_rec
            return record


def verify_security_chain(file_path: str) -> tuple[bool, int, list[str]]:
    errors: list[str] = []
    expected_prev = ZERO_HASH
    count = 0
    with open(file_path, "r", encoding="utf-8") as f:
        for idx, raw in enumerate(f, start=1):
            line = raw.strip()
            if not line:
                continue
            count += 1
            if TOKEN_PREFIX_RE.search(line):
                errors.append(f"рядок {idx}: виявлено немаскований секрет/токен")
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                errors.append(f"рядок {idx}: некоректний JSON")
                continue
            stored_hash = rec.pop("entry_hash", None)
            if rec.get("prev_hash") != expected_prev:
                errors.append(f"рядок {idx}: ланцюг SHA-256 розірвано (prev_hash не збігається)")
            canonical = json.dumps(rec, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
            calc_hash = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
            if stored_hash != calc_hash:
                errors.append(f"рядок {idx}: ланцюг SHA-256 розірвано (рядок змінено)")
            expected_prev = stored_hash or expected_prev
    return len(errors) == 0, count, errors