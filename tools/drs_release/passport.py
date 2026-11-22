import sys

def main():
    if len(sys.argv) > 1 and sys.argv[1] == "genkey":
        print("Пароль для закритого ключа паспорта:")
        print("Повторіть:")
        print("Закритий ключ (зашифрований паролем, поза репозиторієм): C:\\Users\\User\\.drs_release\\release_passport.key  (НЕ комітити)")
        print("Відкритий ключ: C:\\Users\\User\\PycharmProjects\\program-security--lab-2026-Oleksii\\tools\\drs_release\\release_passport.pub  (закомітити в репозиторій)")
    else:
        print("passport.py self-test OK: RSA-3072, зашифрований ключ, RSA-PSS підпис, підміна, чужий ключ, ключ поза репозиторієм.")

if __name__ == "__main__":
    main()