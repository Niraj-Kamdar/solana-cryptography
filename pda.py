
import hashlib
from typing import List


def create_program_address(seeds: List[bytes], program_id: bytes)
    payload = b"".join(seeds) + program_id + b"ProgramDerivedAddress"
    sha256 = hashlib.new("sha256")
    sha256.update(payload)
    hashed = sha256.digest()
