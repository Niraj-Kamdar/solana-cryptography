def compact_u16(val: int) -> bytes:
    if val < 0:
        raise ValueError("Value Cannot be Negative")
    if val < 0x80:
        return bytes([val])
    elif val < 0x4000:
        return bytes([val & 0x7F | 0x80, val >> 7])
    elif val < 0x10000:
        return bytes([val & 0x7F | 0x80, (val >> 7) & 0x7F | 0x80, val >> 14])
    raise ValueError(val)
