import hashlib
import time


def read_target_hash():
    with open("targets.txt", "r", encoding="utf-8") as f:
        for line in f:
            if line.startswith("sha256:"):
                return line.strip().split(":", 1)[1]
    return None


def main():
    target_hash = read_target_hash()
    if not target_hash:
        print("Ціль SHA-256 не знайдено в targets.txt")
        return

    print(f"Ціль SHA-256: {target_hash}")

    with open("dictionary.txt", "r", encoding="utf-8") as f:
        words = [line.strip("\n") for line in f.readlines()]
    print(f"Слів у словнику: {len(words)}")

    start_time = time.perf_counter()
    attempts = 0
    found = False

    for word in words:
        attempts += 1
        word_hash = hashlib.sha256(word.encode('utf-8')).hexdigest()
        if word_hash == target_hash:
            found = True
            break

    end_time = time.perf_counter()
    duration = end_time - start_time
    speed = attempts / duration if duration > 0 else 0

    if found:
        print(f"ЗНАЙДЕНО за {attempts} спроб: '{word}'")
    else:
        print(f"НЕ ЗНАЙДЕНО за {attempts} спроб.")

    print(f"Час: {duration:.4f} с. Швидкість: {speed:,.0f} спроб/с")
    print(
        "\nВисновок: SHA-256 - швидка хеш-функція, тому навіть простий перебір «пробиває» словниковий пароль практично миттєво. Саме тому паролі не можна зберігати під SHA-256 — для цього є bcrypt/scrypt/Argon2.")


if __name__ == "__main__":
    main()