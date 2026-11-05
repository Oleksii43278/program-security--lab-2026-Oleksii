import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

# 1. Формуємо відкритий текст
student_str = "2026_КБЗІ-24-1_Матвєєв_Олексій_варіант:10"
p1 = student_str.encode('utf-8')

# 2. Генеруємо випадкові ключ та вектор (IV)
key1 = os.urandom(32) # AES-256
iv1 = os.urandom(16)

# 3. Легітимне шифрування
cipher = Cipher(algorithms.AES(key1), modes.CTR(iv1), backend=default_backend())
encryptor = cipher.encryptor()
c1 = encryptor.update(p1) + encryptor.finalize()

print("Крок 4 — легітимне шифрування (знають ключ):")
print(f"Відкритий текст №1       {p1.hex()}")
print(f"Ключ №1                  {key1.hex()}")
print(f"Вектор №1 (IV/лічильник) {iv1.hex()}")
print(f"Шифротекст №1            {c1.hex()}\n")

# 4. Атака (відомі лише P1, C1, алгоритм)
# Знаходимо гаму (Keystream) = C1 XOR P1
keystream = bytes(a ^ b for a, b in zip(c1, p1))
print("Крок 5 — атака (ключ НЕВІДОМИЙ, відомі лише P1, C1, алгоритм):")
print(f"Гама №1 = C1 XOR P1      {keystream.hex()}")

# Формуємо альтернативний текст
alt_str = "2026_КБЗІ-24-1_Матвєєв_Олексій_варіант:99"
p2 = alt_str.encode('utf-8')

print(f"Альт. текст (варіант 99) {p2.hex()}")

# Підробляємо шифротекст: C2 = P2 XOR Гама
c2 = bytes(a ^ b for a, b in zip(p2, keystream))
print(f"Шифротекст №2 (підробка) {c2.hex()}\n")

# 5. Перевірка
print("Крок 6 — перевірка: «жертва» штатно розшифровує C2 своїм ключем:")
decryptor = cipher.decryptor()
decrypted_p2 = decryptor.update(c2) + decryptor.finalize()

print(f"Розшифровано з C2        {decrypted_p2.hex()}")
print(f"Текст: {decrypted_p2.decode('utf-8')}\n")

print("Висновок: не знаючи ключа, за однією парою (P1, C1) відновлено гаму й підроблено")
print("валідний шифротекст довільного тексту тієї самої довжини; жертва розшифрувала саме")
print("підставлений текст. CTR забезпечує конфіденційність, але не виявляє підміни й не")
print("прощає повторне використання (key, IV). Для цілісності — автентифіковане шифрування (AES-GCM).")