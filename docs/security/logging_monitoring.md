# Логування та моніторинг на серверній стороні (TaleSpire GM Hub)

## 1. Структура запису та рівні логування
- **Формат:** JSON Lines (`.jsonl`), один структурований запис на рядок (виключає розрив стектрейсами).
- **Часова основа:** єдина мітка `ts` в **UTC ISO 8601** із мілісекундами (`YYYY-MM-DDTHH:MM:SS.mmmZ`).
- **Обов'язкові поля:** `ts`, `level`, `event` (`домен.дія`), `component`, `version`, `pid`; атрибути кореляції — `request_id` (збігається із заголовком відповіді `X-Request-ID`), `ip`, `client_id`, `token_fp` (12 hex SHA-256).
- **Рівні:** `DEBUG` (лише розробка), `INFO` (штатні події), `WARNING` (відмови `4xx`, блокування, алерти, помилки TLS), `ERROR` (помилки операцій `5xx`), `CRITICAL` (загроза доступності сервісу).

## 2. Події, що реєструються
- Життєвий цикл сервера (`server.initialized`), адміністрування (`admin.client_added`).
- Автентифікація та сеанси (`auth.token_issued`, `auth.token_revoked`, `auth.denied` із причиною та лічильником невдач).
- Авторизація (`authz.forbidden` із необхідним скоупом), критичні бізнес-операції (`release.published`).
- Доступ HTTP (`http.access`: метод, маршрут, статус, байти, `duration_ms`), помилки TLS (`tls.handshake_failed`) та сповіщення (`alert.raised`).

## 3. Захист чутливих даних
- Заборонено записувати: паролі, `client_secret`, сирі токени (`gmh_...`, `gms_...`), заголовки `Authorization`, закриті ключі.
- Реалізовано автоматичне рекурсивне редагування (`redact_value` / `redact_text`) із заміною чутливих полів і шаблонів `Bearer`/`Basic` на `[REDACTED]`, а для ідентифікації токена використовується лише `token_fp`.

## 4. Моніторинг, алерти та зберігання
- **Показники (`GET /api/v1/metrics`, скоуп `audit:read`):** `uptime_s`, `total_requests`, `requests_5m`, `auth_failures_5m`, `errors_5xx_1m`, `latency_ms` (`p50`/`p95`), розподіл за статусами й маршрутами.
- **Правила сповіщень:** `auth.lockout` (5 невдач клієнта), `auth.bruteforce_ip` ($\ge 8$ невдач із IP за 60 с), `http.scan_404` ($\ge 10$ кодів 404 за 60 с), `authz.forbidden_spike` ($\ge 5$ кодів 403 за 60 с), `http.server_error_spike` ($\ge 3$ коди 5xx за 60 с).
- **Зберігання та цілісність:** добова ротація (UTC), окремі файли `gm_hub-YYYY-MM-DD.jsonl` (14 діб) і `gm_security-YYYY-MM-DD.jsonl` (90 діб) поза репозиторієм; безпековий журнал захищено криптографічним ланцюгом SHA-256 (`prev_hash` → `entry_hash`).