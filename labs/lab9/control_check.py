CONTROL = "2026_КБЗІ-24-1_Матвєєв_Олексій_варіант:10_"


def main() -> None:
    value = input("Введіть контрольне значення: ")
    if value == CONTROL:
        print("Доступ дозволено")
    else:
        print("Доступ заборонено")


if __name__ == "__main__":
    main()