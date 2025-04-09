import math
import time
from typing import Tuple, Union

from py_avdu.hashes import get_hash

class TOTP:
    def __init__(self, code: int, digits: int):
        self._code = code
        self._digits = digits

    def code(self) -> int:
        """Returns the raw code used for calculating the OTP."""
        return self._code

    def digits(self) -> int:
        """Returns the character/digit length of the OTP."""
        return self._digits

    def __str__(self) -> str:
        """Returns the calculated OTP used to authenticate with a service."""
        code_mod = self._code % int(math.pow(10, self._digits))
        return f"{code_mod:0{self._digits}d}"


def generate_totp(secret: bytes, algo: str, digits: int, period: int) -> Tuple[Union[TOTP, None], Union[None, Exception]]:
    """Generates a TOTP for the current time."""
    return generate_totp_at(secret, algo, digits, period, int(time.time()))


def generate_totp_at(secret: bytes, algo: str, digits: int, period: int, seconds: int) -> Tuple[Union[TOTP, None], Union[None, Exception]]:
    """Generates a TOTP at the specified time in seconds."""
    try:
        counter = int(math.floor(seconds / period))
        secret_hash = get_hash(secret, algo, counter)

        offset = secret_hash[-1] & 0x0F
        otp = int(
            ((secret_hash[offset] & 0x7F) << 24) |
            ((secret_hash[offset + 1] & 0xFF) << 16) |
            ((secret_hash[offset + 2] & 0xFF) << 8) |
            (secret_hash[offset + 3] & 0xFF)
        )

        return TOTP(code=otp, digits=digits), None
    except Exception as e:
        return None, e


