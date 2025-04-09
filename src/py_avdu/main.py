import sys
import pathlib
import json
import pprint

from .classes import KeyParams, Params, Header, Slot, VaultEncrypted

def main(args = sys.argv[1:]):
    vault_path, pwd = args

    vault_dict = json.loads(pathlib.Path(vault_path).read_text())

    encrypted = VaultEncrypted(**vault_dict)

    master_key = encrypted.find_master_key(pwd)

    del pwd

    decrypted = encrypted.decrypt_vault(master_key)

    del master_key

    pprint.pprint(decrypted.db)

    del decrypted


if __name__ == '__main__':
    main()