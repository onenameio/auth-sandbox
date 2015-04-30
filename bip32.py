from pybitcointools import bip32_master_key, bip32_ckd, bip32_privtopub, \
    bip32_extract_key
from utilitybelt import int_to_hex, hex_to_int, dev_random_entropy, \
    dev_urandom_entropy
from binascii import hexlify


def gen_31bit_num():
    first_7_bits = int_to_hex(hex_to_int(hexlify(dev_random_entropy(1))) % 128)
    last_24_bits = hexlify(dev_random_entropy(3))
    return hex_to_int(first_7_bits + last_24_bits)


def gen_8bit_num():
    return hex_to_int(hexlify(dev_random_entropy(1)))


def print_keys(priv, pub, index):
    print "index: %s\npriv: %s\npub: %s\n" % (str(index), priv, pub)


def create_master_keypair(seed, keyprint=False):
    priv_master = bip32_master_key(seed)
    pub_master = bip32_privtopub(priv_master)
    if keyprint:
        print_keys(priv_master, pub_master, "master")
    return priv_master, pub_master


def extract_index_number(index):
    if isinstance(index, int):
        return index

    if not isinstance(index, str):
        raise ValueError("Index must be a string or an integer.")

    shift = 0
    if "h" in index:
        index = index.replace("h", "")
        shift = 2**31

    try:
        return int(index) + shift
    except:
        raise ValueError('Index must be a string composed of an integer '
                         'and an optional "h" suffix.')


def gen_descendent_keys(priv_parent, descendent_path,
                        parent_path=[], keyprint=False):
    if len(descendent_path) == 0:
        pub_parent = bip32_privtopub(priv_parent)
        print_keys(priv_parent, pub_parent, "m/" + "/".join(parent_path))
        return priv_parent, pub_parent

    index = extract_index_number(descendent_path[0])

    priv_child = bip32_ckd(priv_parent, index)
    pub_child = bip32_privtopub(priv_child)

    new_parent_path = parent_path + [str(descendent_path[0])]
    new_descendent_path = descendent_path[1:]

    return gen_descendent_keys(
        priv_child, new_descendent_path, parent_path=new_parent_path,
        keyprint=keyprint)


def gen_128bit_chain(account_id=None):
    """ Make sure the account number has at least 4 bits of entropy.
    """
    if not account_id:
        account_id = str(gen_8bit_num()) + 'h'
    chain = [account_id, gen_31bit_num(), gen_31bit_num(),
             gen_31bit_num(), gen_31bit_num()]
    return chain


def main():
    print ""
    seed = 'c635ba4a5340e3185a2a36e7aa95a0d0b94b4ef3ffedcd6f51aae27a72c571a9'
    priv_master, pub_master = create_master_keypair(seed, keyprint=True)

    # priv_0, pub_0 = gen_descendent_keys(priv_master, [0], keyprint=True)
    # priv_1, pub_1 = gen_descendent_keys(priv_master, [1], keyprint=True)
    # priv_00, pub_00 = gen_descendent_keys(priv_master, [0, 0], keyprint=True)
    # priv_0h, pub_0h = gen_descendent_keys(priv_master, ["0h"], keyprint=True)

    # chain = ["44h", "0h", "0h", "0", "0"]
    # priv, pub = gen_descendent_keys(priv_master, chain, keyprint=True)

    # account_id = '87h'
    priv, pub = gen_descendent_keys(
        priv_master, gen_128bit_chain(), keyprint=True)

if __name__ == '__main__':
    main()


"""
def create_child_keypair(priv_parent, index):
    pub_parent = bip32_privtopub(priv_parent)
    priv_child = bip32_ckd(priv_parent, index)
    pub_child = bip32_ckd(pub_parent, index)
    assert pub_child == bip32_privtopub(priv_child)
    return priv_child, pub_child

"""
