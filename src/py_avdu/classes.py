import sys
import pathlib
import base64
import json
import pprint
from binascii import hexlify, unhexlify
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.backends import default_backend

class VaultEncrypted:
    def __init__(self, version=None, header=None, db=None):
        self.Version = version
        self.Header = header
        self.Db = db
    
    def find_master_key(self, pwd):
        """
        Uses the password to decrypt the master key from the vault and returns the master key's bytes.
        """
        key = None
        master_key = None
        
        for slot in self.Header.Slots:
            # Ignore slots that aren't using the password type
            if slot.Type != 1:
                continue
                
            salt = unhexlify(slot.Salt)
            
            # Create a key using the slot values and provided password
            kdf = Scrypt(
                salt=salt,
                length=32,
                n=slot.N,
                r=slot.R,
                p=slot.P,
                backend=default_backend()
            )
            key = kdf.derive(pwd.encode())
            
            nonce = unhexlify(slot.KeyParams.Nonce)
            tag = unhexlify(slot.KeyParams.Tag)
            slot_key = unhexlify(slot.Key)
            
            # Combine slot key and tag for decryption
            key_data = slot_key + tag
            
            # Attempt to decrypt the master key
            try:
                aesgcm = AESGCM(key)
                master_key = aesgcm.decrypt(nonce, key_data, None)
                # If decryption succeeds, break out of the loop
                break
            except Exception:
                # Continue to the next slot if decryption fails
                continue
        
        if master_key is None or len(master_key) == 0:
            raise ValueError("no master key found")
            
        return master_key
    
    def decrypt_contents(self, master_key):
        """
        Uses the master key to decrypt the vault's contents and returns the content's bytes.
        """
        db_str = self.Db
        params = self.Header.Params
        
        nonce = unhexlify(params.Nonce)
        tag = unhexlify(params.Tag)
        db_data = base64.b64decode(db_str)
        
        # Combine database data and tag for decryption
        database = db_data + tag
        
        # Attempt to decrypt the vault content
        try:
            aesgcm = AESGCM(master_key)
            content = aesgcm.decrypt(nonce, database, None)
            return content
        except Exception as e:
            raise e
    
    def decrypt_vault(self, master_key):
        """
        Decrypts the vault's contents and returns a plaintext version of the vault.
        """
        content = self.decrypt_contents(master_key)
        
        # Parse the JSON content
        db = json.loads(content.decode('utf-8'))
        
        # Create a plaintext vault with decrypted content
        vault_data_plain = Vault(
            version=self.Version,
            header=self.Header,
            db=db
        )
        
        return vault_data_plain


class Vault:
    def __init__(self, version=None, header=None, db=None):
        self.Version = version
        self.Header = header
        self.Db = db


# These classes would need to be defined to match the Go struct definitions
class Header:
    def __init__(self, slots=None, params=None):
        self.Slots = slots or []
        self.Params = params


class Slot:
    def __init__(self, type=0, uuid="", salt="", n=0, r=0, p=0, key_params=None, key="", repaired = False, is_backup = False):
        self.Type = type
        self.Salt = salt
        self.N = n
        self.R = r
        self.P = p
        self.KeyParams = key_params
        self.Key = key


class Params:
    def __init__(self, nonce="", tag=""):
        self.Nonce = nonce
        self.Tag = tag


class KeyParams:
    def __init__(self, nonce="", tag=""):
        self.Nonce = nonce
        self.Tag = tag
