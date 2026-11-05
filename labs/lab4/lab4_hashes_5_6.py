import hashlib
import bcrypt

target_str = "pass: Матвєєв"
target_bytes = target_str.encode('utf-8')

print(f"Рядок: '{target_str}'")
print(f"Символів: {len(target_str)}, байтів UTF-8: {len(target_bytes)}\n")

# Хеш №5 (SHA-256)
hash_5 = hashlib.sha256(target_bytes).hexdigest()
print(f"Хеш №5 (SHA-256):               {hash_5}")

# Хеш №6 (bcrypt, cost=12)
hash_6 = bcrypt.hashpw(target_bytes, bcrypt.gensalt(rounds=12))
print(f"Хеш №6 (bcrypt, cost=12):       {hash_6.decode('utf-8')}\n")

# Записуємо цілі у файл для скриптів перебору
with open("targets.txt", "w", encoding="utf-8") as f:
    f.write(f"sha256:{hash_5}\n")
    f.write(f"bcrypt:{hash_6.decode('utf-8')}\n")

print("Записано у targets.txt: рядки sha256:... і bcrypt:... для скриптів перебору.")
print("Примітка: bcrypt щоразу бере нову сіль, тому Хеш №6 буде іншим за кожного запуску -")
print("це нормально; checkpw усе одно підтверджує пароль, бо сіль зберігається всередині хеша.")