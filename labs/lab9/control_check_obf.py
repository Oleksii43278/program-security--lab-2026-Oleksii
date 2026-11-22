import hashlib
import hmac


def _p0(n: int) -> bool:
    return ((n * n * n - n) % 6) == 0


def _x1(s: str) -> str:
    return s[::2][::-1]


def _k2(val: str) -> bytes:
    return hashlib.sha256(val.encode("utf-8")).digest()


def _b3() -> str:
    _pool = {
        7: "1a-b4c2d-eІfЗgБhК",
        3: "6x2q0z2",
        9: "DECOY_999",
        2: "вxєyєzвkтmаpМ",
        5: "йqіwсeкrеtлyО",
        1: "тuнiаoіpрaаsв",
        4: "admin_root",
    }
    _sep = chr(0x3F ^ 0x60)
    _col = chr(0x1A ^ 0x20)
    _num = str(0x2A ^ 0x20)

    _st = 3
    _noise = 0x4B
    _out = []

    while _st != 0:
        _noise = ((_noise * 5 + 17) ^ _st) & 0xFF
        match _st:
            case 3:
                _out.append(_x1(_pool[3]) if _p0(_noise) else _pool[9])
                _st = 11
            case 11:
                _out.append(_sep)
                _st = 7
            case 7:
                _out.append(_x1(_pool[7]))
                _st = 14
            case 14:
                _out.append(_sep if _p0(_st) else "?")
                _st = 2
            case 2:
                _out.append(_x1(_pool[2]))
                _st = 9
            case 9:
                _out.append(_sep)
                _st = 5
            case 5:
                _out.append(_x1(_pool[5]) if _p0(_noise + 1) else _pool[4])
                _st = 12
            case 12:
                _out.append(_sep)
                _st = 1
            case 1:
                _out.append(_x1(_pool[1]))
                _st = 8
            case 8:
                _out.append(_col + _num)
                _st = 6
            case 6:
                _out.append(_sep)
                _st = 0
            case 4 | 13:
                _out.append(_pool[4][::-1])
                _st = 0
            case _:
                _st = 0

    return "".join(_out)


def _run() -> None:
    _inp = input("Введіть контрольне значення: ")
    _fn = getattr(
        hmac,
        "".join(chr(c) for c in (99, 111, 109, 112, 97, 114, 101, 95, 100, 105, 103, 101, 115, 116)),
    )
    if _fn(_k2(_b3()), _k2(_inp)):
        print("Доступ дозволено")
    else:
        print("Доступ заборонено")


if __name__ == "__main__":
    _run()