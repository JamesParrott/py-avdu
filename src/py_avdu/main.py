import sys
import pathlib
import json

from .classes import KeyParams, Params, Header, Slot, VaultEncrypted

def main(args = sys.argv[1:]):
    vault_path, pwd = args

    vault_dict = json.loads(pathlib.Path(vault_path).read_text())

    header_dict = vault_dict['header']

    slots = []
    for slot_dict in header_dict['slots']:
        key_params = KeyParams(**slot_dict['key_params'])
        slot_args = {**slot_dict, 'key_params' : key_params}
        slot = Slot(**slot_args)
        slots.append(slot)

    params = Params(**header_dict['params'])

    version = vault_dict['version']
    header = Header(slots=slots, params = params)
    db = vault_dict['db']

    encrypted = VaultEncrypted(version, header, db)

    master_key = encrypted.find_master_key(pwd)

    decrypted = encrypted.decrypt_vault(master_key)

    del master_key

    pprint.pprint(decrypted.Db)


if __name__ == '__main__':
    main()