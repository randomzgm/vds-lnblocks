import hashlib
from ecdsa import SECP256k1, SigningKey
import sys
import binascii
import reverse_hex

# 58 character alphabet used
BASE58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'


def from_bytes(data, big_endian=False):
    if isinstance(data, str):
        data = bytearray(data)
    if big_endian:
        data = reversed(data)
    num = 0
    for offset, byte in enumerate(data):
        num += byte << (offset * 8)
    return num


def base58_encode(version, public_address, log=True):
    """
    Gets a Base58Check string
    See https://en.bitcoin.it/wiki/Base58Check_encoding
    """
    if sys.version_info.major > 2:
        version = bytes.fromhex(version)
    else:
        version = bytearray.fromhex(version)
    firstSHA256 = hashlib.sha256(version + public_address)
    if log:
        print("first sha256: %s" % firstSHA256.hexdigest())
    secondSHA256 = hashlib.sha256(firstSHA256.digest())
    if log:
        print("second sha256: %s" % secondSHA256.hexdigest())
    checksum = secondSHA256.digest()[:4]
    payload = version + public_address + checksum
    # payload = binascii.a2b_hex('101c3fb9db6847e6fff5d3ee495a8c470433a543a501235a84bd')
    if log:
        print("Hex address: %s" % binascii.hexlify(payload).decode())
    if sys.version_info.major > 2:
        result = int.from_bytes(payload, byteorder="big")
    else:
        result = from_bytes(payload, True)
    # count the leading 0s
    padding = len(payload) - len(payload.lstrip(b'\0'))
    encoded = []

    while result != 0:
        result, remainder = divmod(result, 58)
        encoded.append(BASE58_ALPHABET[remainder])

    return padding * "1" + "".join(encoded)[::-1]


def get_private_key(hex_string):
    if sys.version_info.major > 2:
        return bytes.fromhex(hex_string.zfill(64))
    else:
        return bytearray.fromhex(hex_string.zfill(64))


def get_public_key(key):
    # this returns the concatenated x and y coordinates for the supplied private address
    # the prepended 04 is used to signify that it's uncompressed
    if sys.version_info.major > 2:
        return bytes.fromhex("04") + SigningKey.from_string(key, curve=SECP256k1).verifying_key.to_string()
    else:
        return (bytearray.fromhex("04") + SigningKey.from_string(key,
                                                                 curve=SECP256k1).verifying_key.to_string())


def get_public_address(key):
    address = hashlib.sha256(key).digest()
    print("public key hash256: %s" % hashlib.sha256(key).hexdigest())
    h = hashlib.new('ripemd160')
    h.update(address)
    address = h.digest()
    print("RIPEMD-160: %s" % h.hexdigest())
    return address


if __name__ == "__main__":
    # private_key = get_private_key("FEEDB0BDEADBEEF")
    private_key = get_private_key("18e14a7b6a307f426a94f8114701e7c8e774e7f9a47e2c2035db29a206321725")
    # print("private key: %s" % binascii.hexlify(private_key).decode())
    # public_key = get_public_key(private_key)
    public_key = binascii.a2b_hex('04a43578ea8e66c6431382aec31d43873678899018893d83ea4819123f32eb327dc8970ef9b41afff40ecbc309fd70353205d1c26ea4fdd871cf583c790b345434')
    print("public_key: %s" % binascii.hexlify(public_key).decode())
    public_address = get_public_address(public_key)
    # public_address = binascii.a2b_hex('6c50777bc3b841c883ffefa1d25d95cb4bb7469a')
    bitcoin_address = base58_encode("101c", public_address)
    print("Final address %s" % bitcoin_address)
