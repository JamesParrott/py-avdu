import base64
import json
from binascii import hexlify, unhexlify
from typing import List, Any
from pydantic import BaseModel
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.backends import default_backend


class KeyParams(BaseModel):
    nonce: str
    tag: str


class Params(BaseModel):
    nonce: str
    tag: str


class Slot(BaseModel):
    type: int
    salt: str
    n: int
    r: int
    p: int
    key_params: KeyParams
    key: str


class Header(BaseModel):
    slots: List[Slot]
    params: Params


class VaultEncrypted(BaseModel):
    version: int
    header: Header
    db: str
    
    def find_master_key(self, pwd):
        """
        Uses the password to decrypt the master key from the vault and returns the master key's bytes.
        """
        key = None
        master_key = None
        
        for slot in self.header.slots:
            # Ignore slots that aren't using the password type
            if slot.type != 1:
                continue
                
            salt = unhexlify(slot.salt)
            
            # Create a key using the slot values and provided password
            kdf = Scrypt(
                salt=salt,
                length=32,
                n=slot.n,
                r=slot.r,
                p=slot.p,
                backend=default_backend()
            )
            key = kdf.derive(pwd.encode())
            
            nonce = unhexlify(slot.key_params.nonce)
            tag = unhexlify(slot.key_params.tag)
            slot_key = unhexlify(slot.key)
            
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
        db_str = self.db
        params = self.header.params
        
        nonce = unhexlify(params.nonce)
        tag = unhexlify(params.tag)
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
        db_content = json.loads(content.decode('utf-8'))
        
        # Create a plaintext vault with decrypted content
        vault_data_plain = Vault(
            version=self.version,
            header=self.header,
            db=db_content
        )
        
        return vault_data_plain


class Vault(BaseModel):
    version: int
    header: Header
    db: Any  # This will be the parsed JSON content