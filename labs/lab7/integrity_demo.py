import os
import hashlib
import hmac
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# 1. SHA-256 і лавинний ефект (кроки 3-4)
print("--- SHA-256 і лавинний ефект (кроки 3-4) ---")
base_str = "2026_КБЗІ-24-1_Матвєєв_Олексій_варіант:10"
hash1 = hashlib.sha256(base_str.encode('utf-8')).hexdigest()
print(f"Хеш №1: {hash1}")

# Змінюємо один символ (наприклад, 10 на 90)
alt_str = "2026_КБЗІ-24-1_Матвєєв_Олексій_варіант:90"
hash2 = hashlib.sha256(alt_str.encode('utf-8')).hexdigest()
print(f"Хеш №2: {hash2} (змінено один символ)")

# Рахуємо кількість змінених бітів
h1_bytes = bytes.fromhex(hash1)
h2_bytes = bytes.fromhex(hash2)
diff_bits = sum(bin(b1 ^ b2).count('1') for b1, b2 in zip(h1_bytes, h2_bytes))
print(f"Відмінність: {diff_bits} із 256 бітів (~половина — лавинний ефект).\n")


# 2. HMAC-SHA256 (кроки 5-9)
print("--- HMAC-SHA256 (кроки 5-9) ---")
key1 = os.urandom(32)
print(f"Ключ №1: {key1.hex()}")

mac1 = hmac.new(key1, base_str.encode('utf-8'), hashlib.sha256).hexdigest()
print(f"HMAC №1: {mac1}")

# Перевірка зміненого повідомлення
mac_alt_msg = hmac.new(key1, alt_str.encode('utf-8'), hashlib.sha256).hexdigest()
if hmac.compare_digest(mac1, mac_alt_msg):
    print("Перевірка зміненого повідомлення проти HMAC №1: УСПІШНО (це помилка)")
else:
    print("Перевірка зміненого повідомлення проти HMAC №1: НЕВДАЛО")

# Створюємо ключ, змінений на 1 біт (XOR останнього байта з 0x01)
key2 = bytearray(key1)
key2[-1] ^= 0x01
key2 = bytes(key2)

# Перевірка з неправильним ключем
mac_bad_key = hmac.new(key2, base_str.encode('utf-8'), hashlib.sha256).hexdigest()
if hmac.compare_digest(mac1, mac_bad_key):
    print("Перевірка з ключем (1 біт змінено) проти HMAC №1: УСПІШНО (це помилка)")
else:
    print("Перевірка з ключем (1 біт змінено) проти HMAC №1: НЕВДАЛО")

print(f"HMAC №2: {mac_bad_key}")
mac1_bytes = bytes.fromhex(mac1)
mac2_bytes = bytes.fromhex(mac_bad_key)
diff_bits_mac = sum(bin(b1 ^ b2).count('1') for b1, b2 in zip(mac1_bytes, mac2_bytes))
print(f"Відмінність HMAC №1/№2 при зміні 1 біта ключа: {diff_bits_mac} із 256 бітів.\n")


# 3. AES-GCM: виявлення підміни (кроки 10-11)
print("--- AES-GCM: виявлення підміни (кроки 10-11) ---")
aes_key = os.urandom(32)
nonce = os.urandom(12)
aesgcm = AESGCM(aes_key)

print(f"Ключ:   {aes_key.hex()}")
print(f"Nonce:  {nonce.hex()}")

ct = aesgcm.encrypt(nonce, base_str.encode('utf-8'), None)
print(f"Шифротекст+мітка: {ct.hex()}")

# Штатне розшифрування
pt = aesgcm.decrypt(nonce, ct, None)
print(f"Штатне розшифрування: {pt.decode('utf-8')}")

# Змінюємо один байт шифротексту
bad_ct = bytearray(ct)
bad_ct[0] ^= 0x01
bad_ct = bytes(bad_ct)

try:
    aesgcm.decrypt(nonce, bad_ct, None)
    print("Змінений шифротекст розшифровано УСПІШНО (це помилка, підміну не виявлено).")
except Exception as e:
    # exception will usually be cryptography.exceptions.InvalidTag
    print(f"Зміну одного байта шифротексту виявлено: InvalidTag — дані відхилено.\n")

print("Висновок: SHA-256 виявляє зміну, лише якщо еталонний хеш захищено від підміни; проти")
print("активного порушника потрібні HMAC (спільний секрет) або цифровий підпис, а для даних,")
print("що й шифруються, — автентифіковане шифрування (AES-GCM). Вибір залежить від моделі загроз.")