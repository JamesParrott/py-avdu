import sys
import pathlib
import json
import pprint

from py_avdu.encrypted_classes import KeyParams, Params, Header, Slot, VaultEncrypted
from py_avdu.decrypted_classes import Db
from py_avdu.totp import generate_totp_code

def main(args = sys.argv[1:]):
    vault_path, pwd = args

    vault_dict = json.loads(pathlib.Path(vault_path).read_text())

    encrypted = VaultEncrypted(**vault_dict)

    master_key = encrypted.find_master_key(pwd)

    del pwd

    decrypted = encrypted.decrypt_vault(master_key)

    del master_key

    pprint.pprint(decrypted.db)

    db_plain = Db(**decrypted.db)

    del decrypted

    for entry in db_plain.entries:
        info = entry.info
        totp_code =  generate_totp_code(info.secret.encode(), info.algo, info.period)
        print(f'{entry.issuer}, {entry.name}, {totp_code} ')

    del entry, info, db_plain



if __name__ == '__main__':
    main()