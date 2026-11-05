import bcrypt
import time


def read_target_hash():
    with open("targets.txt", "r", encoding="utf-8") as f:
        for line in f:
            if line.startswith("bcrypt:"):
                return line.strip().split(":", 1)[1]
    return None


def main():
    target_hash = read_target_hash()
    if not target_hash:
        print("Ціль bcrypt не знайдено в targets.txt")
        return

    target_hash_bytes = target_hash.encode('utf-8')
    # Знаходимо вартість (cost) з хешу (напр., $2b$12$ -> 12)
    cost = target_hash.split("$")[2]

    print(f"Ціль bcrypt: {target_hash[:20]}...")
    print(f"Вартість (cost): {cost}")

    with open("dictionary.txt", "r", encoding="utf-8") as f:
        words = [line.strip("\n") for line in f.readlines()]
    print(f"Слів у словнику: {len(words)}")

    start_time = time.perf_counter()
    attempts = 0
    found = False

    for word in words:
        attempts += 1
        word_bytes = word.encode('utf-8')
        if bcrypt.checkpw(word_bytes, target_hash_bytes):
            found = True
            break

    end_time = time.perf_counter()
    duration = end_time - start_time
    speed = attempts / duration if duration > 0 else 0

    if found:
        print(f"ЗНАЙДЕНО за {attempts} спроб: '{word}'")
    else:
        print(f"НЕ ЗНАЙДЕНО за {attempts} спроб.")

    print(f"Час: {duration:.4f} с. Швидкість: {speed:.1f} спроб/с")


if __name__ == "__main__":
    main()