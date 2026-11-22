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

ROLE_SCOPES: dict[str, set[str]] = {
    "gm_admin": {"releases:write", "sessions:read", "sessions:write", "audit:read"},
    "player_tester": {"sessions:write", "sessions:read:own"},
    "auditor": {"audit:read", "sessions:read"},
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
    def __init__(self, token_ttl: int = 600, max_failures: int = 5, lock_seconds: int = 300) -> None:
        self.token_ttl = token_ttl
        self.max_failures = max_failures
        self.lock_seconds = lock_seconds
        self.clients: dict[str, dict] = {}
        self.tokens: dict[str, dict] = {}
        self.releases: dict[str, dict] = {}
        self.failures: dict[str, dict] = {}
        self.audit_log: list[str] = []

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
        return raw_secret

    def log(self, event: str, **fields) -> None:
        ts = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        meta = " ".join(f"{k}={v}" for k, v in fields.items())
        self.audit_log.append(f"{ts} {event} {meta}".strip())


class SecureHTTPServer(ThreadingHTTPServer):
    def __init__(self, server_address, handler_cls, state: HubState):
        super().__init__(server_address, handler_cls)
        self.state = state

    def handle_error(self, request, client_address) -> None:
        pass


class GMHubHandler(BaseHTTPRequestHandler):
    server_version = "TaleSpireGMHub/1.0"

    def log_message(self, format, *args) -> None:
        pass

    def _send_json(self, status: int, body: dict, extra_headers: dict | None = None) -> None:
        req_id = secrets.token_hex(6)
        payload = dict(body)
        if status >= 400:
            payload.setdefault("request_id", req_id)
        raw = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("Pragma", "no-cache")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Request-ID", req_id)
        if extra_headers:
            for k, v in extra_headers.items():
                self.send_header(k, v)
        self.end_headers()
        self.wfile.write(raw)

    def _read_body(self, max_bytes: int = 16384) -> bytes | None:
        length = int(self.headers.get("Content-Length", "0"))
        if length > max_bytes:
            self._send_json(413, {"error": "payload_too_large", "message": "Request body exceeds limit"})
            return None
        return self.rfile.read(length) if length > 0 else b""

    def _require_token(self, required_scope: str | None = None) -> tuple[str, dict] | None:
        auth = self.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            self._send_json(
                401,
                {"error": "unauthorized", "message": "Bearer token required"},
                {"WWW-Authenticate": 'Bearer realm="gm-hub"'},
            )
            return None
        raw_token = auth[7:].strip()
        tok_hash = sha256_hex(raw_token)
        rec = self.server.state.tokens.get(tok_hash)
        if not rec or rec["revoked"] or rec["expires_at"] <= time.time():
            self._send_json(
                401,
                {"error": "invalid_token", "message": "Token is invalid, expired or revoked"},
                {"WWW-Authenticate": 'Bearer realm="gm-hub"'},
            )
            return None
        client = self.server.state.clients.get(rec["client_id"])
        if not client or not client["enabled"]:
            self._send_json(401, {"error": "invalid_token", "message": "Client disabled"})
            return None
        if required_scope and required_scope not in rec["scopes"]:
            self.server.state.log("auth.forbidden", client_id=rec["client_id"], need=required_scope)
            self._send_json(
                403,
                {"error": "insufficient_scope", "message": f"Required scope: {required_scope}"},
            )
            return None
        return tok_hash, rec

    def do_GET(self) -> None:
        path = urlparse(self.path).path.rstrip("/") or "/"
        state: HubState = self.server.state

        if path == "/api/v1/health":
            self._send_json(200, {"status": "ok", "service": "gm-hub", "version": "1.0.0"})
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

        if path == "/api/v1/audit":
            auth = self._require_token("audit:read")
            if not auth:
                return
            self._send_json(200, {"entries": len(state.audit_log), "tail": state.audit_log[-10:]})
            return

        self._send_json(404, {"error": "not_found", "message": "Route not found"})

    def do_POST(self) -> None:
        path = urlparse(self.path).path.rstrip("/") or "/"
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
                self._send_json(
                    400,
                    {"error": "invalid_request", "message": "Basic client authentication required"},
                )
                return

            grant_type = form.get("grant_type", [""])[0]
            if grant_type != "client_credentials":
                self._send_json(
                    400,
                    {"error": "unsupported_grant_type", "message": "Only client_credentials is allowed"},
                )
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
                state.log("auth.locked", client_id=client_id, retry_after=retry_after)
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
                if fail_rec["count"] >= state.max_failures:
                    fail_rec["locked_until"] = now + state.lock_seconds
                state.log("auth.denied", client_id=client_id, failures=fail_rec["count"])
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
            state.tokens[tok_hash] = {
                "client_id": client_id,
                "role": client["role"],
                "scopes": granted,
                "expires_at": now + state.token_ttl,
                "revoked": False,
            }
            state.log("auth.token_issued", client_id=client_id, role=client["role"], token_fp=tok_hash[:12])
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
            state.log("auth.token_revoked", client_id=rec["client_id"], token_fp=tok_hash[:12])
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
            state.log("release.published", version=ver, by=rec["client_id"], token_fp=tok_hash[:12])
            self._send_json(201, {"status": "created", "version": ver, "published_by": rec["client_id"]})
            return

        self._send_json(404, {"error": "not_found", "message": "Route not found"})


def start_https_server(state: HubState, cert_path: str, key_path: str, port: int = 0) -> SecureHTTPServer:
    srv = SecureHTTPServer(("127.0.0.1", port), GMHubHandler, state)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(certfile=cert_path, keyfile=key_path)
    srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    return srv