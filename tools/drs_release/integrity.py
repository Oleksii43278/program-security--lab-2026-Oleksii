import os
import hashlib
import json
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature

PRIVATE_KEY_FILE = "drs_release.signing.key"
PUBLIC_KEY_FILE = "release_signing.pub"
MANIFEST_FILE = "MANIFEST.sha256"
SIG_FILE = "MANIFEST.sha256.sig"


def generate_ed25519_keys():
    """Генерує пару ключів Ed25519 для підпису релізів."""
    if os.path.exists(PRIVATE_KEY_FILE):
        print(f"Приватний ключ {PRIVATE_KEY_FILE} вже існує!")
        return False

    private_key = ed25519.Ed25519PrivateKey.generate()
    public_key = private_key.public_key()

    # Зберігаємо приватний ключ (доступ лише для власника 0o600)
    priv_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    # Створюємо файл з безпечними правами (на Unix-системах)
    fd = os.open(PRIVATE_KEY_FILE, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, 'wb') as f:
        f.write(priv_bytes)

    # Зберігаємо відкритий ключ
    pub_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    with open(PUBLIC_KEY_FILE, "wb") as f:
        f.write(pub_bytes)

    print(f"Приватний ключ: {PRIVATE_KEY_FILE} (НЕ комітити!)")
    print(f"Відкритий ключ: {PUBLIC_KEY_FILE} (закомітити в репозиторій)")
    return True


def hash_file(filepath):
    """Обчислює SHA-256 хеш файлу."""
    sha256 = hashlib.sha256()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            sha256.update(chunk)
    return sha256.hexdigest()


def build_manifest(directory):
    """Будує маніфест SHA-256 для всіх файлів у теці (крім самого маніфесту та підпису)."""
    manifest = {}
    for root, _, files in os.walk(directory):
        for file in files:
            if file in [MANIFEST_FILE, SIG_FILE]:
                continue
            filepath = os.path.join(root, file)
            rel_path = os.path.relpath(filepath, directory).replace("\\", "/")
            manifest[rel_path] = hash_file(filepath)

    manifest_path = os.path.join(directory, MANIFEST_FILE)
    with open(manifest_path, "w", encoding="utf-8") as f:
        for rel_path, f_hash in sorted(manifest.items()):
            f.write(f"{f_hash} *{rel_path}\n")
    return len(manifest)


def sign_manifest(directory):
    """Підписує маніфест закритим ключем Ed25519."""
    if not os.path.exists(PRIVATE_KEY_FILE):
        return False, "Приватний ключ не знайдено."

    manifest_path = os.path.join(directory, MANIFEST_FILE)
    if not os.path.exists(manifest_path):
        return False, "Маніфест не знайдено."

    with open(PRIVATE_KEY_FILE, "rb") as f:
        private_key = serialization.load_pem_private_key(f.read(), password=None)

    with open(manifest_path, "rb") as f:
        manifest_data = f.read()

    signature = private_key.sign(manifest_data)

    sig_path = os.path.join(directory, SIG_FILE)
    with open(sig_path, "wb") as f:
        f.write(signature)

    return True, "Маніфест підписано Ed25519"


def verify_manifest(directory):
    """Перевіряє підпис маніфесту та цілісність усіх файлів у теці."""
    if not os.path.exists(PUBLIC_KEY_FILE):
        return False, ["Відкритий ключ не знайдено."]

    manifest_path = os.path.join(directory, MANIFEST_FILE)
    sig_path = os.path.join(directory, SIG_FILE)

    if not os.path.exists(manifest_path) or not os.path.exists(sig_path):
        return False, ["Маніфест або підпис не знайдено."]

    # 1. Перевірка підпису (автентичність)
    with open(PUBLIC_KEY_FILE, "rb") as f:
        public_key = serialization.load_pem_public_key(f.read())

    with open(manifest_path, "rb") as f:
        manifest_data = f.read()

    with open(sig_path, "rb") as f:
        signature = f.read()

    try:
        public_key.verify(signature, manifest_data)
    except InvalidSignature:
        return False, ["Недійсний цифровий підпис маніфесту!"]

    # 2. Перевірка хешів файлів (цілісність)
    errors = []
    expected_files = {}
    with open(manifest_path, "r", encoding="utf-8") as f:
        for line in f:
            parts = line.strip().split(" *", 1)
            if len(parts) == 2:
                expected_files[parts[1]] = parts[0]

    actual_files = set()
    for root, _, files in os.walk(directory):
        for file in files:
            if file in [MANIFEST_FILE, SIG_FILE]:
                continue
            filepath = os.path.join(root, file)
            rel_path = os.path.relpath(filepath, directory).replace("\\", "/")
            actual_files.add(rel_path)

            if rel_path not in expected_files:
                errors.append(f"зайвий: {rel_path}")
            elif hash_file(filepath) != expected_files[rel_path]:
                errors.append(f"змінено: {rel_path}")

    for missing in set(expected_files.keys()) - actual_files:
        errors.append(f"відсутній: {missing}")

    if errors:
        return False, errors
    return True, ["Підпис маніфесту дійсний і вміст теки збігається."]


def self_test():
    """Самоперевірка модуля."""
    if not os.path.exists(PRIVATE_KEY_FILE):
        generate_ed25519_keys()

    os.makedirs("test_dir", exist_ok=True)
    with open("test_dir/test.txt", "w") as f:
        f.write("hello")

    build_manifest("test_dir")
    sign_manifest("test_dir")

    ok, _ = verify_manifest("test_dir")
    assert ok, "Штатна перевірка не пройдена"

    # Модифікація
    with open("test_dir/test.txt", "w") as f:
        f.write("hello world")
    ok, errs = verify_manifest("test_dir")
    assert not ok and "змінено: test.txt" in errs[0], "Зміну не виявлено"

    # Прибираємо сліди
    os.remove("test_dir/test.txt")
    os.remove(f"test_dir/{MANIFEST_FILE}")
    os.remove(f"test_dir/{SIG_FILE}")
    os.rmdir("test_dir")

    print("integrity.py self-test OK: маніфест, виявлення зміни, Ed25519-підпис.")


if __name__ == "__main__":
    import sys

    if len(sys.argv) > 1 and sys.argv[1] == "genkey":
        generate_ed25519_keys()
    else:
        self_test()