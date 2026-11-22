import copy
import datetime
import hashlib
import json
import time

ZERO_HASH = "0" * 64


def canonical_json(obj: dict) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def compute_block_hash(block: dict) -> str:
    body = {
        "index": block["index"],
        "timestamp": block["timestamp"],
        "data": block["data"],
        "prev_hash": block["prev_hash"],
        "nonce": block["nonce"],
    }
    return hashlib.sha256(canonical_json(body).encode("utf-8")).hexdigest()


def mine_block(index: int, data: str, prev_hash: str, difficulty: int) -> tuple[dict, int]:
    prefix = "0" * difficulty
    ts = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    nonce = 0
    attempts = 0
    while True:
        block = {
            "index": index,
            "timestamp": ts,
            "data": data,
            "prev_hash": prev_hash,
            "nonce": nonce,
        }
        h = compute_block_hash(block)
        attempts += 1
        if h.startswith(prefix):
            block["hash"] = h
            return block, attempts
        nonce += 1


def verify_chain(chain: list[dict], difficulty: int) -> tuple[bool, list[str]]:
    prefix = "0" * difficulty
    errors: list[str] = []
    for i, blk in enumerate(chain):
        if blk["index"] != i:
            errors.append(f"блок {i}: некоректний індекс ({blk['index']})")
        expected_prev = ZERO_HASH if i == 0 else chain[i - 1]["hash"]
        if blk["prev_hash"] != expected_prev:
            errors.append(f"блок {i}: prev_hash не збігається з хешем блока {i - 1} (зв'язок розірвано)")
        actual_hash = compute_block_hash(blk)
        if blk["hash"] != actual_hash:
            errors.append(
                f"блок {i}: власний хеш не відповідає вмісту "
                f"(збережений {blk['hash'][:16]}... != фактичний {actual_hash[:16]}...)"
            )
        if not blk["hash"].startswith(prefix):
            errors.append(f"блок {i}: хеш не задовольняє складність PoW ({difficulty} нулів)")
    return len(errors) == 0, errors


def print_chain(title: str, chain: list[dict]) -> None:
    print(f"\n=== {title} ===")
    print(f"{'№':>2} | {'nonce':>7} | {'prev_hash':<16} | {'hash':<16} | дані")
    print(f"{'-'*2}-+-{'-'*7}-+-{'-'*16}-+-{'-'*16}-+-{'-'*46}")
    for b in chain:
        print(f"{b['index']:>2} | {b['nonce']:>7} | {b['prev_hash'][:16]} | {b['hash'][:16]} | {b['data']}")


def main() -> None:
    difficulty = 4
    events = [
        "Genesis — ЛР13-14, КБЗІ-24-1, Матвєєв Олексій, варіант 10",
        "TaleSpire GM Logger 1.0.0: базовий реліз і підпис Ed25519",
        "TaleSpire GM Logger 1.1.0: паспорт релізу RSA-PSS (ЛР8)",
        "gm_hub 1.0.0: HTTPS + OAuth 2.0 Client Credentials (ЛР10-11)",
        "gm_hub 1.1.0: JSONL-логування, метрики та алерти (ЛР12)",
        "gm_hub 1.2.0: наскрізне шифрування сесій та хеш-ланцюг (ЛР13-14)",
    ]

    chain: list[dict] = []
    total_hashes = 0
    t0 = time.perf_counter()
    for idx, text in enumerate(events):
        prev = ZERO_HASH if idx == 0 else chain[-1]["hash"]
        blk, att = mine_block(idx, text, prev, difficulty)
        chain.append(blk)
        total_hashes += att
    dt = time.perf_counter() - t0

    print(
        f"Побудовано Genesis + 5 блоків (PoW складність {difficulty}): "
        f"{total_hashes} обчислень SHA-256 за {dt:.2f} с "
        f"(~{total_hashes // len(events)} на блок; теоретично ~{16 ** difficulty})"
    )
    print_chain("1. Початковий ланцюг", chain)

    t_v = time.perf_counter()
    ok, errs = verify_chain(chain, difficulty)
    print(f"Перевірка ({(time.perf_counter() - t_v) * 1000:.3f} мс): {'ЛАНЦЮГ ЦІЛИЙ' if ok else errs}")
    anchor_head = chain[-1]["hash"]
    print(f"Збережений зовнішній якір (голова ланцюга): {anchor_head}")

    # 2а. Зміна даних блока 2 без перерахунку хешу
    tampered_a = copy.deepcopy(chain)
    tampered_a[2]["data"] = "TaleSpire GM Logger 9.9.9: ПІДМІНЕНИЙ паспорт релізу"
    ok_a, errs_a = verify_chain(tampered_a, difficulty)
    print("\n=== 2а. Змінено дані блока 2 без перерахунку хешу ===")
    print("Результат:", "OK" if ok_a else "ПОРУШЕННЯ -> " + " | ".join(errs_a))

    # 2б. Перемайнили лише блок 2, наступні не чіпали
    tampered_b = copy.deepcopy(tampered_a)
    remined_2, _ = mine_block(2, tampered_b[2]["data"], tampered_b[1]["hash"], difficulty)
    tampered_b[2] = remined_2
    ok_b, errs_b = verify_chain(tampered_b, difficulty)
    print("\n=== 2б. Перераховано і перемайнено лише блок 2 ===")
    print("Результат:", "OK" if ok_b else "ПОРУШЕННЯ -> " + " | ".join(errs_b))

    # 3. Повторне формування блока 2 і всього хвоста (блоки 2–5)
    rebuilt = copy.deepcopy(chain[:2])
    rebuild_hashes = 0
    t1 = time.perf_counter()
    for idx in range(2, len(chain)):
        data_i = tampered_a[idx]["data"] if idx == 2 else chain[idx]["data"]
        blk, att = mine_block(idx, data_i, rebuilt[-1]["hash"], difficulty)
        rebuilt.append(blk)
        rebuild_hashes += att
    dt_r = time.perf_counter() - t1

    print_chain("3. Блок 2 і всі наступні (2–5) сформовано повторно", rebuilt)
    ok_r, errs_r = verify_chain(rebuilt, difficulty)
    new_head = rebuilt[-1]["hash"]
    print(f"Внутрішня перевірка: {'ЛАНЦЮГ ЦІЛИЙ' if ok_r else errs_r}")
    print(f"Ціна переписування хвоста (4 блоки): {rebuild_hashes} обчислень SHA-256 за {dt_r:.2f} с")
    print(f"Нова голова ланцюга:    {new_head}")
    print(f"Збіг із якорем?         {'ТАК' if new_head == anchor_head else 'НІ — підміну історії виявлено за якорем!'}")


if __name__ == "__main__":
    main()