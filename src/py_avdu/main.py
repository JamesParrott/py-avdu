import sys
import pathlib
import json
import pprint

import pyotp

from py_avdu.encrypted_classes import KeyParams, Params, Header, Slot, VaultEncrypted
from py_avdu.decrypted_classes import Db


def main(args = sys.argv[1:]):
    vault_path, pwd = args

    sys.argv.clear()
    args.clear()

    vault_dict = json.loads(pathlib.Path(vault_path).read_text())

    encrypted = VaultEncrypted(**vault_dict)

    master_key = encrypted.find_master_key(pwd)

    del pwd

    decrypted = encrypted.decrypt_vault(master_key)

    del master_key

    db_plain = Db(**decrypted.db)

    del decrypted

    for entry in db_plain.entries:
        info = entry.info
        totp = pyotp.TOTP(info.secret)
        print(f'{entry.issuer}, {entry.name}: {totp.now()} ')

    del entry, info, db_plain, totp



if __name__ == '__main__':
    main()