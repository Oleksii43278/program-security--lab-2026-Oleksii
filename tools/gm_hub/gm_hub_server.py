import base64
import datetime
import hashlib
import hmac
import ipaddress
import json
import secrets
import ssl
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from gm_hub_e2ee import ALG_NAME
from gm_hub_ledger import HubLedger
from gm_hub_logging import HubLogger, HubMetrics

ROLE_SCOPES: dict[str, set[str]] = {
    "gm_admin": {"releases:write", "sessions:read", "sessions:write", "audit:read", "ledger:read"},
    "player_tester": {"sessions:write", "sessions:read:own"},
    "auditor": {"audit:read", "ledger:read"},
}


def sha256_hex(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def generate_ca_and_server_certs(ca_cert_path: str, srv_cert_path: str, srv_key_path: str) -> str:
    now = datetime.datetime.now(datetime.timezone.utc)

    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "TaleSpire GM Hub Local CA")])
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=False,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), critical=False)
        .sign(ca_key, hashes.SHA256())
    )

    srv_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    srv_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "127.0.0.1")])
    srv_cert = (
        x509.CertificateBuilder()
        .subject_name(srv_name)
        .issuer_name(ca_name)
        .public_key(srv_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.SubjectAlternativeName([
                x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")),
                x509.DNSName("localhost"),
            ]),
            critical=False,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=True,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())
    )

    with open(ca_cert_path, "wb") as f:
        f.write(ca_cert.public_bytes(serialization.Encoding.PEM))
    with open(srv_cert_path, "wb") as f:
        f.write(srv_cert.public_bytes(serialization.Encoding.PEM))
    with open(srv_key_path, "wb") as f:
        f.write(
            srv_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )
    return hashlib.sha256(ca_cert.public_bytes(serialization.Encoding.DER)).hexdigest()[:16].upper()


class HubState:
    def __init__(
        self,
        log_dir: str | None = None,
        token_ttl: int = 600,
        max_failures: int = 5,
        lock_seconds: int = 300,
    ) -> None:
        self.version = "1.2.0"
        self.token_ttl = token_ttl
        self.max_failures = max_failures
        self.lock_seconds = lock_seconds
        self.clients: dict[str, dict] = {}
        self.tokens: dict[str, dict] = {}
        self.releases: dict[str, dict] = {}
        self.sessions: dict[str, dict] = {}
        self.recipient_kids: set[str] = set()
        self.failures: dict[str, dict] = {}
        self.ledger = HubLedger()
        self.logger = HubLogger(log_dir=log_dir, version=self.version)
        self.metrics = HubMetrics()
        self.logger.emit("INFO", "server.initialized", security=True, tls=True, token_ttl_s=token_ttl)

    def register_recipient_kid(self, kid: str) -> None:
        self.recipient_kids.add(kid)

    def add_client(self, client_id: str, role: str) -> str:
        if role not in ROLE_SCOPES:
            raise ValueError(f"Unknown role: {role}")
        raw_secret = "gms_" + secrets.token_urlsafe(32)
        self.clients[client_id] = {
            "secret_hash": sha256_hex(raw_secret),
            "role": role,
            "scopes": set(ROLE_SCOPES[role]),
            "enabled": True,
        }
        self.logger.emit("INFO", "admin.client_added", security=True, client_id=client_id, role=role)
        return raw_secret

    def emit_alerts(self, alerts: list[dict], request_id: str | None, ip: str | None) -> None:
        for alert in alerts:
            self.logger.emit(
                "WARNING",
                "alert.raised",
                security=True,
                request_id=request_id,
                ip=ip,
                rule=alert["rule"],
                subject=alert["subject"],
                count=alert["count"],
                window_s=alert["window_s"],
            )


class SecureHTTPServer(ThreadingHTTPServer):
    def __init__(self, server_address, handler_cls, state: HubState):
        super().__init__(server_address, handler_cls)
        self.state = state

    def handle_error(self, request, client_address) -> None:
        self.state.logger.emit(
            "WARNING",
            "tls.handshake_failed",
            security=True,
            ip=client_address[0] if client_address else "unknown",
        )


class GMHubHandler(BaseHTTPRequestHandler):
    server_version = "TaleSpireGMHub/1.2"

    def log_message(self, format, *args) -> None:
        pass

    def _begin_request(self, path: str) -> None:
        self._req_id = secrets.token_hex(8)
        self._start_ts = time.perf_counter()
        self._route_name = path
        self._client_id: str | None = None
        self._token_fp: str | None = None
        self._client_ip = self.client_address[0] if self.client_address else "unknown"

    def _send_json(self, status: int, body: dict, extra_headers: dict | None = None) -> None:
        payload = dict(body)
        if status >= 400:
            payload.setdefault("request_id", self._req_id)
        raw = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("Pragma", "no-cache")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Request-ID", self._req_id)
        if extra_headers:
            for k, v in extra_headers.items():
                self.send_header(k, v)
        self.end_headers()
        self.wfile.write(raw)

        duration_ms = round((time.perf_counter() - self._start_ts) * 1000.0, 2)
        state: HubState = self.server.state
        alerts = state.metrics.record_http(self._route_name, status, self._client_ip, duration_ms)
        state.logger.emit(
            "WARNING" if status >= 400 else "INFO",
            "http.access",
            security=False,
            request_id=self._req_id,
            ip=self._client_ip,
            client_id=self._client_id,
            token_fp=self._token_fp,
            method=self.command,
            path=self._route_name,
            status=status,
            bytes=len(raw),
            duration_ms=duration_ms,
        )
        state.emit_alerts(alerts, self._req_id, self._client_ip)

    def _read_body(self, max_bytes: int = 32768) -> bytes | None:
        length = int(self.headers.get("Content-Length", "0"))
        if length > max_bytes:
            self._send_json(413, {"error": "payload_too_large", "message": "Request body exceeds limit"})
            return None
        return self.rfile.read(length) if length > 0 else b""

    def _require_token(
        self,
        required_scope: str | None = None,
        any_scopes: set[str] | None = None,
    ) -> tuple[str, dict] | None:
        state: HubState = self.server.state
        auth = self.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            state.logger.emit(
                "WARNING",
                "auth.denied",
                security=True,
                request_id=self._req_id,
                ip=self._client_ip,
                route=self._route_name,
                reason="missing_bearer",
            )
            self._send_json(
                401,
                {"error": "unauthorized", "message": "Bearer token required"},
                {"WWW-Authenticate": 'Bearer realm="gm-hub"'},
            )
            return None

        raw_token = auth[7:].strip()
        tok_hash = sha256_hex(raw_token)
        rec = state.tokens.get(tok_hash)
        if not rec or rec["revoked"] or rec["expires_at"] <= time.time():
            state.logger.emit(
                "WARNING",
                "auth.denied",
                security=True,
                request_id=self._req_id,
                ip=self._client_ip,
                route=self._route_name,
                reason="invalid_or_revoked_token",
            )
            self._send_json(
                401,
                {"error": "invalid_token", "message": "Token is invalid, expired or revoked"},
                {"WWW-Authenticate": 'Bearer realm="gm-hub"'},
            )
            return None

        client = state.clients.get(rec["client_id"])
        if not client or not client["enabled"]:
            self._send_json(401, {"error": "invalid_token", "message": "Client disabled"})
            return None

        self._client_id = rec["client_id"]
        self._token_fp = tok_hash[:12]

        if required_scope and required_scope not in rec["scopes"]:
            state.logger.emit(
                "WARNING",
                "authz.forbidden",
                security=True,
                request_id=self._req_id,
                ip=self._client_ip,
                client_id=self._client_id,
                token_fp=self._token_fp,
                route=self._route_name,
                required_scope=required_scope,
            )
            self._send_json(
                403,
                {"error": "insufficient_scope", "message": f"Required scope: {required_scope}"},
            )
            return None

        if any_scopes and not (rec["scopes"] & any_scopes):
            need = " or ".join(sorted(any_scopes))
            state.logger.emit(
                "WARNING",
                "authz.forbidden",
                security=True,
                request_id=self._req_id,
                ip=self._client_ip,
                client_id=self._client_id,
                token_fp=self._token_fp,
                route=self._route_name,
                required_scope=need,
            )
            self._send_json(403, {"error": "insufficient_scope", "message": f"Required scope: {need}"})
            return None
        return tok_hash, rec

    def do_GET(self) -> None:
        path = urlparse(self.path).path.rstrip("/") or "/"
        self._begin_request(path)
        state: HubState = self.server.state

        if path == "/api/v1/health":
            self._send_json(200, {"status": "ok", "service": "gm-hub", "version": state.version})
            return

        if path == "/api/v1/releases":
            public_items = [
                {k: v for k, v in rel.items() if k != "published_by"}
                for rel in state.releases.values()
            ]
            self._send_json(200, {"count": len(public_items), "releases": public_items})
            return

        if path == "/api/v1/whoami":
            auth = self._require_token()
            if not auth:
                return
            tok_hash, rec = auth
            self._send_json(
                200,
                {
                    "client_id": rec["client_id"],
                    "role": rec["role"],
                    "scope": " ".join(sorted(rec["scopes"])),
                    "token_fp": tok_hash[:12],
                },
            )
            return

        if path == "/api/v1/metrics":
            auth = self._require_token("audit:read")
            if not auth:
                return
            self._send_json(200, state.metrics.snapshot())
            return

        if path == "/api/v1/sessions":
            auth = self._require_token(any_scopes={"sessions:read", "sessions:read:own"})
            if not auth:
                return
            _, rec = auth
            can_all = "sessions:read" in rec["scopes"]
            items = []
            for sid, env in state.sessions.items():
                if can_all or env["meta"]["submitter"] == rec["client_id"]:
                    items.append({
                        "session_id": sid,
                        "submitter": env["meta"]["submitter"],
                        "kid": env["kid"],
                        "created": env["meta"].get("created"),
                        "ct_len": len(env["ct"]),
                    })
            self._send_json(200, {"count": len(items), "sessions": items})
            return

        if path.startswith("/api/v1/sessions/"):
            auth = self._require_token(any_scopes={"sessions:read", "sessions:read:own"})
            if not auth:
                return
            _, rec = auth
            sid = path.rsplit("/", 1)[-1]
            env = state.sessions.get(sid)
            can_all = "sessions:read" in rec["scopes"]
            if not env or (not can_all and env["meta"]["submitter"] != rec["client_id"]):
                self._send_json(404, {"error": "not_found", "message": "Session report not found"})
                return
            self._send_json(200, env)
            return

        if path == "/api/v1/ledger":
            auth = self._require_token("ledger:read")
            if not auth:
                return
            self._send_json(200, {"count": len(state.ledger.blocks), "head": state.ledger.head(), "blocks": state.ledger.blocks})
            return

        if path == "/api/v1/ledger/verify":
            auth = self._require_token("ledger:read")
            if not auth:
                return
            ok, errs = state.ledger.verify(state.releases, state.sessions)
            self._send_json(200, {"ok": ok, "blocks": len(state.ledger.blocks), "head": state.ledger.head(), "errors": errs})
            return

        self._send_json(404, {"error": "not_found", "message": "Route not found"})

    def do_POST(self) -> None:
        path = urlparse(self.path).path.rstrip("/") or "/"
        self._begin_request(path)
        state: HubState = self.server.state

        raw = self._read_body()
        if raw is None:
            return

        if path == "/oauth/token":
            form = parse_qs(raw.decode("utf-8", errors="replace"))
            if "client_secret" in form:
                self._send_json(400, {"error": "invalid_request", "message": "Use Authorization: Basic header"})
                return

            auth_hdr = self.headers.get("Authorization", "")
            if not auth_hdr.startswith("Basic "):
                self._send_json(400, {"error": "invalid_request", "message": "Basic client authentication required"})
                return

            grant_type = form.get("grant_type", [""])[0]
            if grant_type != "client_credentials":
                self._send_json(400, {"error": "unsupported_grant_type", "message": "Only client_credentials is allowed"})
                return

            try:
                decoded = base64.b64decode(auth_hdr[6:].strip()).decode("utf-8")
                client_id, client_secret = decoded.split(":", 1)
            except Exception:
                self._send_json(400, {"error": "invalid_request", "message": "Malformed Basic header"})
                return

            now = time.time()
            fail_rec = state.failures.setdefault(client_id, {"count": 0, "locked_until": 0.0})
            if fail_rec["locked_until"] > now:
                retry_after = int(fail_rec["locked_until"] - now) + 1
                state.logger.emit(
                    "WARNING",
                    "auth.denied",
                    security=True,
                    request_id=self._req_id,
                    ip=self._client_ip,
                    client_id_attempt=client_id,
                    reason="locked",
                    retry_after=retry_after,
                )
                alerts = state.metrics.record_auth_failure(self._client_ip, client_id, locked=False)
                state.emit_alerts(alerts, self._req_id, self._client_ip)
                self._send_json(
                    429,
                    {"error": "too_many_attempts", "message": "Client temporarily locked"},
                    {"Retry-After": str(retry_after)},
                )
                return

            client = state.clients.get(client_id)
            valid = bool(
                client
                and client["enabled"]
                and hmac.compare_digest(sha256_hex(client_secret), client["secret_hash"])
            )
            if not valid:
                fail_rec["count"] += 1
                just_locked = fail_rec["count"] >= state.max_failures
                if just_locked:
                    fail_rec["locked_until"] = now + state.lock_seconds
                state.logger.emit(
                    "WARNING",
                    "auth.denied",
                    security=True,
                    request_id=self._req_id,
                    ip=self._client_ip,
                    client_id_attempt=client_id,
                    reason="bad_credentials",
                    failures=fail_rec["count"],
                )
                alerts = state.metrics.record_auth_failure(self._client_ip, client_id, locked=just_locked)
                state.emit_alerts(alerts, self._req_id, self._client_ip)
                self._send_json(
                    401,
                    {"error": "invalid_client", "message": "Client authentication failed"},
                    {"WWW-Authenticate": 'Basic realm="gm-hub"'},
                )
                return

            fail_rec["count"] = 0
            fail_rec["locked_until"] = 0.0

            req_scope_str = form.get("scope", [""])[0].strip()
            if req_scope_str:
                req_scopes = set(req_scope_str.split())
                if not req_scopes.issubset(client["scopes"]):
                    self._send_json(400, {"error": "invalid_scope", "message": "Requested scope exceeds role"})
                    return
                granted = req_scopes
            else:
                granted = set(client["scopes"])

            raw_token = "gmh_" + secrets.token_urlsafe(32)
            tok_hash = sha256_hex(raw_token)
            self._client_id = client_id
            self._token_fp = tok_hash[:12]
            state.tokens[tok_hash] = {
                "client_id": client_id,
                "role": client["role"],
                "scopes": granted,
                "expires_at": now + state.token_ttl,
                "revoked": False,
            }
            state.logger.emit(
                "INFO",
                "auth.token_issued",
                security=True,
                request_id=self._req_id,
                ip=self._client_ip,
                client_id=client_id,
                token_fp=tok_hash[:12],
                role=client["role"],
                expires_in=state.token_ttl,
            )
            self._send_json(
                200,
                {
                    "access_token": raw_token,
                    "token_type": "Bearer",
                    "expires_in": state.token_ttl,
                    "scope": " ".join(sorted(granted)),
                },
            )
            return

        if path == "/oauth/revoke":
            auth = self._require_token()
            if not auth:
                return
            tok_hash, rec = auth
            rec["revoked"] = True
            state.logger.emit(
                "INFO",
                "auth.token_revoked",
                security=True,
                request_id=self._req_id,
                ip=self._client_ip,
                client_id=rec["client_id"],
                token_fp=tok_hash[:12],
            )
            self._send_json(200, {"revoked": True, "token_fp": tok_hash[:12]})
            return

        if path == "/api/v1/releases":
            auth = self._require_token("releases:write")
            if not auth:
                return
            tok_hash, rec = auth
            try:
                body = json.loads(raw.decode("utf-8"))
            except Exception:
                self._send_json(400, {"error": "invalid_json", "message": "Malformed JSON payload"})
                return
            allowed = {"version", "product", "sha256", "tag"}
            extra = set(body.keys()) - allowed
            if extra:
                self._send_json(400, {"error": "unknown_field", "message": f"Disallowed fields: {sorted(extra)}"})
                return
            ver = str(body.get("version", "")).strip()
            if not ver:
                self._send_json(400, {"error": "invalid_request", "message": "version is required"})
                return
            if ver in state.releases:
                self._send_json(409, {"error": "conflict", "message": f"Release {ver} already exists"})
                return
            record = {
                "product": body.get("product", "TaleSpire_GM_Logger_Pro"),
                "version": ver,
                "tag": body.get("tag", f"v{ver}"),
                "sha256": body.get("sha256", ""),
                "published_by": rec["client_id"],
            }
            state.releases[ver] = record
            receipt = state.ledger.append("release", ver, record)
            state.logger.emit(
                "INFO",
                "release.published",
                security=True,
                request_id=self._req_id,
                ip=self._client_ip,
                client_id=rec["client_id"],
                token_fp=tok_hash[:12],
                release_version=ver,
                ledger_idx=receipt["idx"],
            )
            self._send_json(201, {"status": "created", "version": ver, "published_by": rec["client_id"], "receipt": receipt})
            return

        if path == "/api/v1/sessions":
            auth = self._require_token("sessions:write")
            if not auth:
                return
            tok_hash, rec = auth
            try:
                env = json.loads(raw.decode("utf-8"))
            except Exception:
                self._send_json(400, {"error": "invalid_json", "message": "Malformed JSON payload"})
                return
            req_fields = {"v", "alg", "kid", "epk", "nonce", "ct", "meta"}
            if not req_fields.issubset(env.keys()) or env.get("alg") != ALG_NAME:
                self._send_json(400, {"error": "invalid_envelope", "message": "Invalid E2EE envelope format"})
                return
            meta = env.get("meta")
            if not isinstance(meta, dict) or meta.get("submitter") != rec["client_id"]:
                self._send_json(400, {"error": "submitter_mismatch", "message": "meta.submitter must match authenticated client"})
                return
            if env["kid"] not in state.recipient_kids:
                self._send_json(400, {"error": "unknown_recipient_key", "message": "Recipient key id is not registered"})
                return
            sid = str(meta.get("session_id", "")).strip()
            if not sid or sid in state.sessions:
                self._send_json(409, {"error": "conflict", "message": "Duplicate or missing session_id"})
                return
            state.sessions[sid] = env
            receipt = state.ledger.append("session", sid, env)
            state.logger.emit(
                "INFO",
                "session.submitted",
                security=True,
                request_id=self._req_id,
                ip=self._client_ip,
                client_id=rec["client_id"],
                token_fp=tok_hash[:12],
                session_id=sid,
                kid=env["kid"],
                ledger_idx=receipt["idx"],
            )
            self._send_json(201, {"status": "accepted", "session_id": sid, "kid": env["kid"], "receipt": receipt})
            return

        self._send_json(404, {"error": "not_found", "message": "Route not found"})


def start_https_server(state: HubState, cert_path: str, key_path: str, port: int = 0) -> SecureHTTPServer:
    srv = SecureHTTPServer(("127.0.0.1", port), GMHubHandler, state)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(certfile=cert_path, keyfile=key_path)
    srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    return srv