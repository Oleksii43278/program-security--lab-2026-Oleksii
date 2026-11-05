import bcrypt

# 1. Формуємо базовий рядок з твоїми даними
base_str = "2026_КБЗІ-24-1_Матвєєв_10_"
base_bytes = base_str.encode('utf-8')
print(f"bcrypt (pyca) версії 5.0.0, rounds = 10")
print(f"Сирий рядок: {base_str}")
print(f"Символів: {len(base_str)}, байтів UTF-8: {len(base_bytes)}")

# Доповнюємо до 72 байтів символом '_'
padding_length = 72 - len(base_bytes)
str_1 = base_str + ("_" * padding_length)
bytes_1 = str_1.encode('utf-8')

print(f"Доповнено {padding_length} символами '_'.")
print(f"№1 базовий:                 {len(bytes_1)} Б | {str_1}")

# 2. Додаємо '1'
str_2 = str_1 + "1"
bytes_2 = str_2.encode('utf-8')
print(f"№2 базовий + '1':           {len(bytes_2)} Б | {str_2}")

# 3. Додаємо 10 випадкових символів
random_10 = "iu3xSBHo6j"
str_3 = str_1 + random_10
bytes_3 = str_3.encode('utf-8')
print(f"№3 базовий + 10 випадкових: {len(bytes_3)} Б | {str_3}")

# 4. Без останнього символу '_'
str_4 = str_1[:-1]
bytes_4 = str_4.encode('utf-8')
print(f"№4 без останнього '_':      {len(bytes_4)} Б | {str_4}")

# Генерація хешів
print("\nГенеруємо хеші...")
# Бібліотека bcrypt 5.0.0 відхиляє вхід > 72 Б, тому для рядків 2 і 3 ми передаємо перші 72 байти
hash_1 = bcrypt.hashpw(bytes_1, bcrypt.gensalt(rounds=10))
print(f"Хеш №1: {hash_1.decode('utf-8')}")

hash_2 = bcrypt.hashpw(bytes_2[:72], bcrypt.gensalt(rounds=10))
print(f"Хеш №2: {hash_2.decode('utf-8')} [бібліотека відхилила вхід > 72 Б; захешовано перші 72 Б]")

hash_3 = bcrypt.hashpw(bytes_3[:72], bcrypt.gensalt(rounds=10))
print(f"Хеш №3: {hash_3.decode('utf-8')} [бібліотека відхилила вхід > 72 Б; захешовано перші 72 Б]")

hash_4 = bcrypt.hashpw(bytes_4, bcrypt.gensalt(rounds=10))
print(f"Хеш №4: {hash_4.decode('utf-8')}")

# Попарна перевірка
strings_to_check = [
    ("№1 базовий", bytes_1),
    ("№2 базовий + '1'", bytes_2),
    ("№3 базовий + 10 випадкових", bytes_3),
    ("№4 без останнього '_'", bytes_4)
]
hashes = [hash_1, hash_2, hash_3, hash_4]

print("\nМатриця перевірки (рядок \ хеш): checkpw повернув True")
print(f"{'':<28} | Хеш №1 | Хеш №2 | Хеш №3 | Хеш №4 |")
print("-" * 68)
for name, b_val in strings_to_check:
    results = []
    for h in hashes:
        # Під час перевірки також передаємо лише перші 72 байти
        match = bcrypt.checkpw(b_val[:72], h)
        results.append("✓" if match else "X")
    print(f"{name:<28} | {results[0]:^6} | {results[1]:^6} | {results[2]:^6} | {results[3]:^6} |")