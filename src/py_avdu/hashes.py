import hmac
import hashlib
import struct


def get_hash(secret: bytes, algo: str, counter: int) -> bytes:
    """
    Hashes the counter using the secret and specified algo,
    then returns the hash.
    
    Args:
        secret: The secret key as bytes
        algo: The hashing algorithm to use ('SHA1', 'SHA256', 'SHA512', 'MD5')
        counter: The counter value
        
    Returns:
        The calculated hash as bytes
        
    Raises:
        ValueError: If an unsupported algorithm is specified
    """
    # Encode counter in big endian (8 bytes)
    counter_bytes = struct.pack('>Q', counter)
    
    # Use the specified algorithm
    if algo == "SHA1":
        hash_func = hashlib.sha1
    elif algo == "SHA256":
        hash_func = hashlib.sha256
    elif algo == "SHA512":
        hash_func = hashlib.sha512
    elif algo == "MD5":
        hash_func = hashlib.md5
    else:
        raise ValueError(f"unsupported algo {algo!r}")
    
    # Calculate the HMAC hash of the counter
    mac = hmac.new(secret, counter_bytes, hash_func)
    
    # Return the hashed result
    return mac.digest()