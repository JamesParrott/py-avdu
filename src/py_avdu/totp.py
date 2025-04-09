import math
import time

from py_avdu.hashes import get_hash




def generate_totp_code(secret: bytes, algo: str, period: int) -> int:
    """Generates a TOTP for the current time."""
    return generate_totp_code_at(secret, algo, period, int(time.time()))


def generate_totp_code_at(secret: bytes, algo: str, period: int, seconds: int) -> int:
    """Generates a TOTP at the specified time in seconds."""
    counter = math.floor(seconds / period)
    secret_hash = get_hash(secret, algo, counter)


	# Truncate the hash to get the [H/T]OTP value
	# https://tools.ietf.org/html/rfc4226#section-5.4
	# https://github.com/beemdevelopment/Aegis/blob/master/app/src/main/java/com/beemdevelopment/aegis/crypto/otp/HOTP.java#L20
    offset = secret_hash[-1] & 0x0F
    otp = int(
        ((secret_hash[offset] & 0x7F) << 24) |
        ((secret_hash[offset + 1] & 0xFF) << 16) |
        ((secret_hash[offset + 2] & 0xFF) << 8) |
        (secret_hash[offset + 3] & 0xFF)
    )

    return otp



