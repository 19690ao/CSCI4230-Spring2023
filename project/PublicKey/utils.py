import secrets

def is_prime(n: int, k: int = 5) -> bool:
    for _ in range(k):
        a = secrets.randbelow(n)
        if pow(a, n-1, n) != 1:
            return False

    return True


def generate_prime(n: int) -> int:
    res = 4

    while not is_prime(res):
       
        res = (1 << n-1) + (secrets.randbits(n-2) << 1) + 1

    return res


def str_to_num(msg: str) -> int:
    return int.from_bytes(msg.encode('utf-8'), byteorder='big')


def num_to_str(msg: int, size: int) -> str:
    return msg.to_bytes(length=size, byteorder='big').decode('utf-8').strip('\x00')
