import sys
import pathlib
import json
import pprint

import pyotp

from py_avdu.encrypted_classes import KeyParams, Params, Header, Slot, VaultEncrypted
from py_avdu.decrypted_classes import Db
from py_avdu.totp import generate_totp

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
        # totp = pyotp.TOTP(info.secret)
        # print(f'{entry.issuer}, {entry.name}: {totp.now()} ')

        totp, err = generate_totp(info.secret.encode(), info.algo, info.digits, info.period)
        print(f'{entry.issuer}, {entry.name}: {totp} ')

    del entry, info, db_plain, totp

    raise Exception("These codes are incorrect, do not rely on this branch, it is for posterity only")



if __name__ == '__main__':
    main()