import argparse
import hashlib
import http.client
import json
import os
import sys
import time
from urllib.parse import urlparse


class LibraryClient:
    def __init__(self, base_url: str, client_id: str, client_secret: str) -> None:
        parsed = urlparse(base_url)
        if parsed.scheme == "http" and parsed.hostname not in ("127.0.0.1", "localhost"):
            raise ValueError("HTTP без TLS дозволено лише для 127.0.0.1 / localhost")
        self.scheme = parsed.scheme
        self.host = parsed.hostname or "127.0.0.1"
        self.port = parsed.port or (443 if self.scheme == "https" else 80)
        self.client_id = client_id
        self.client_secret = client_secret
        self.access_token: str | None = None
        self.expires_at: float = 0.0

    def _raw_request(self, method: str, path: str, headers: dict | None = None, body: bytes | None = None):
        conn_cls = http.client.HTTPSConnection if self.scheme == "https" else http.client.HTTPConnection
        conn = conn_cls(self.host, self.port, timeout=10)
        try:
            conn.request(method, path, body=body, headers=headers or {})
            resp = conn.getresponse()
            raw = resp.read().decode("utf-8", errors="replace")
            try:
                data = json.loads(raw) if raw else {}
            except json.JSONDecodeError:
                data = {"raw": raw}
            return resp.status, data
        finally:
            conn.close()

    def authenticate(self) -> tuple[int, dict]:
        payload = json.dumps({
            "client_id": self.client_id,
            "client_secret": self.client_secret,
        }).encode("utf-8")
        status, data = self._raw_request(
            "POST",
            "/auth/token",
            headers={"Content-Type": "application/json"},
            body=payload,
        )
        if status == 200 and "access_token" in data:
            self.access_token = data["access_token"]
            self.expires_at = time.time() + int(data.get("expires_in", 1800))
        return status, data

    def _ensure_token(self) -> None:
        if not self.access_token or time.time() >= (self.expires_at - 30):
            status, data = self.authenticate()
            if status != 200:
                raise RuntimeError(f"Помилка автентифікації ({status}): {data}")

    def api_get(self, path: str) -> tuple[int, dict]:
        self._ensure_token()
        status, data = self._raw_request("GET", path, headers={"Authorization": f"Bearer {self.access_token}"})
        if status == 401:
            self.authenticate()
            status, data = self._raw_request("GET", path, headers={"Authorization": f"Bearer {self.access_token}"})
        return status, data


def print_table(rows: list[dict], cols: list[str]) -> None:
    widths = {c: max(len(c), *(len(str(r.get(c, ""))) for r in rows)) for c in cols}
    header = " | ".join(c.ljust(widths[c]) for c in cols)
    sep = "-+-".join("-" * widths[c] for c in cols)
    print(header)
    print(sep)
    for r in rows:
        print(" | ".join(str(r.get(c, "")).ljust(widths[c]) for c in cols))


def main() -> None:
    parser = argparse.ArgumentParser(description="Клієнт навчального REST API бібліотеки")
    parser.add_argument("--url", default="http://127.0.0.1:8080")
    parser.add_argument("--client-id", default=os.environ.get("LAB10_CLIENT_ID", "jasmine-10"))
    parser.add_argument("--negative", action="store_true", help="Виконати також негативні перевірки")
    args = parser.parse_args()

    secret = os.environ.get("LAB10_CLIENT_SECRET")
    if not secret:
        print("Встановіть змінну середовища LAB10_CLIENT_SECRET перед запуском.", file=sys.stderr)
        sys.exit(1)

    client = LibraryClient(args.url, args.client_id, secret)

    st, pub = client._raw_request("GET", "/")
    print(f"=== Публічний опис сервісу (GET /) [HTTP {st}] ===")
    print(f"service: {pub.get('service')} | version: {pub.get('version')}")
    print("public_routes:", ", ".join(pub.get("public_routes", [])))
    print("protected_routes:", ", ".join(pub.get("protected_routes", [])))

    st, tok = client.authenticate()
    fp = hashlib.sha256((client.access_token or "").encode()).hexdigest()[:12]
    print(f"\n=== Автентифікація (POST /auth/token) [HTTP {st}] ===")
    print(f"token_type: {tok.get('token_type')} | expires_in: {tok.get('expires_in')}s | variant: {tok.get('variant')} | watermark: {tok.get('watermark')} | token_fp: {fp}")

    st, me = client.api_get("/whoami")
    print(f"\n=== Поточний читач (GET /whoami) [HTTP {st}] ===")
    for k, v in me.items():
        print(f"  {k}: {v}")

    st, books_resp = client.api_get("/api/books")
    books = books_resp.get("books", [])
    print(f"\n=== Список книг (GET /api/books) [HTTP {st}] — {len(books)} шт. ===")
    if books:
        print_table(books, ["id", "catalog_no", "title", "author", "year", "available"])
        first_id = books[0]["id"]
        st_one, one = client.api_get(f"/api/books/{first_id}")
        print(f"\n=== Деталі книги (GET /api/books/{first_id}) [HTTP {st_one}] ===")
        print(json.dumps(one, ensure_ascii=False, indent=2))

    st, loans_resp = client.api_get("/api/loans")
    loans = loans_resp.get("loans", [])
    print(f"\n=== Активні позики (GET /api/loans) [HTTP {st}] — {len(loans)} шт. ===")
    if loans:
        print_table(loans, ["loan_id", "book_id", "title", "issued_at", "due_at", "status"])

    st, summary = client.api_get("/api/summary")
    print(f"\n=== Зведення (GET /api/summary) [HTTP {st}] ===")
    for k, v in summary.items():
        print(f"  {k}: {v}")

    if args.negative:
        print("\n=== Негативні перевірки ===")
        for label, m, p, hdrs in [
            ("Без токена", "GET", "/api/books", {}),
            ("Підроблений токен", "GET", "/api/books", {"Authorization": "Bearer fake-token"}),
            ("Неіснуюча книга", "GET", "/api/books/does-not-exist", {"Authorization": f"Bearer {client.access_token}"}),
            ("Невірний метод", "GET", "/auth/token", {}),
        ]:
            ns, nd = client._raw_request(m, p, headers=hdrs)
            print(f"[{label}] {m} {p} -> HTTP {ns}: {nd}")


if __name__ == "__main__":
    main()