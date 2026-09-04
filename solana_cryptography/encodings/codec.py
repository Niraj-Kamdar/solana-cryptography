def generic_decode(alphabet: str, string: str) -> bytes:
    order = 0
    length = len(alphabet)
    pad = len(string) - len(string.lstrip(alphabet[0]))
    val = 0
    for c in string[::-1]:
        i = alphabet.index(c)
        val += i * (length**order)
        order += 1
    byte_length = (val.bit_length() + 7) // 8
    return b"\x00" * pad + val.to_bytes(byte_length, "big")


def generic_encode(alphabet: str, data: bytes) -> str:
    length = len(alphabet)
    val = int.from_bytes(data, "big")
    pad = len(data)  - len(data.lstrip(b"\x00"))

    chars = []
    while val:
        val, remainder = divmod(val, length)
        char = alphabet[remainder]
        chars.append(char)
    return alphabet[0] * pad + "".join(reversed(chars))
