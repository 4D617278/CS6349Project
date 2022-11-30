import argparse

from nacl.hash import sha256
from nacl.utils import random
from nacl.encoding import RawEncoder

from config import SIGNATURE_SIZE, HASH_OUTPUT_SIZE

MIN_PORT = 0
MAX_PORT = 65535


def raw_sha256(message):
    return sha256(message, encoder=RawEncoder)

def allowed_ports(port):
    int_port = int(port)
    if MIN_PORT <= int_port <= MAX_PORT:
        return int_port 
    raise argparse.ArgumentTypeError(f"{MIN_PORT} <= port <= {MAX_PORT}")

def sign_hash(message, signing_key, hash_function=raw_sha256):
    hashed_message = hash_function(message)
    print(f"Hashed message: {hashed_message} of length {len(hashed_message)}")
    signed_message = signing_key.sign(hashed_message)
    return signed_message

def encrypt_and_sign(message, box, signing_key, hash_function=raw_sha256):
    print(f"Original message: {message} of length {len(message)}")
    encrypted_message = box.encrypt(message)
    print(f"Encrypted message: {encrypted_message} of length {len(encrypted_message)}")
    signed_hash = sign_hash(encrypted_message, signing_key, hash_function)
    print(f"Signed hash: {signed_hash} of length {len(signed_hash)}")
    return signed_hash + encrypted_message

def get_signature_and_message(message):
    signed_message, encrypted_message = message[:SIGNATURE_SIZE], message[SIGNATURE_SIZE:]
    return signed_message, encrypted_message

def decrypt_and_verify(message, box, verify_key):
    signed_hash, encrypted_message = get_signature_and_message(message)
    print(f"Encrypted message: {encrypted_message} of length {len(encrypted_message)}")
    print(f"Signed hash: {signed_hash} of length {len(signed_hash)}")
    decrypted_message = box.decrypt(encrypted_message)
    print(f"Decrypted message: {decrypted_message} of length {len(decrypted_message)}")
    verify_key.verify(signed_hash)
    return decrypted_message

def xor(byte_arr1, byte_arr2):
    return bytes(x ^ y for (x, y) in zip(byte_arr1, byte_arr2))

def pad(key, block_size=64):
    padding = bytearray(block_size - len(key))
    return key + padding

def compute_block_sized_key(key, block_size=HASH_OUTPUT_SIZE, hash_function=raw_sha256):
    if len(key) > block_size:
        key = hash_function(key)
    if len(key) < block_size:
        return pad(key, block_size)
    return key

def hmac(key, message, block_size=HASH_OUTPUT_SIZE, hash_function=raw_sha256):
    block_sized_key = compute_block_sized_key(key)
    opad = b"\x5c" * block_size
    ipad = b"\x36" * block_size
    o_key_pad = xor(block_sized_key, opad)
    i_key_pad = xor(block_sized_key, ipad)
    return hash_function(o_key_pad + hash_function(i_key_pad + message))

def keyed_hash_encryption(key, message, block_size=HASH_OUTPUT_SIZE, hash_function=raw_sha256):
    # Encryption using HMAC-256 keystream in cipher feedback mode
    key_byte_arr = bytearray(key)
    message_byte_arr = bytearray(message)
    # print(f"Length of plaintext: {len(message_byte_arr)}")
    iv = hash_function(key)
    output = key_byte_arr
    encrypted = bytearray()
    prev_enc = iv
    for i in range(0, len(message_byte_arr), HASH_OUTPUT_SIZE):
        block = message_byte_arr[i:i+HASH_OUTPUT_SIZE]
        output = hmac(iv, prev_enc)
        enc = xor(block, output)
        prev_enc = enc
        encrypted += enc
        # print(f"Block offset: {i}:\nplaintext: {block}\noutput: {output}\nciphertext: {enc}\n")
    # print(f"Length of encrypted value: {len(encrypted)}")
    return encrypted

def keyed_hash_decryption(key, message, block_size=HASH_OUTPUT_SIZE, hash_function=raw_sha256):
    # Decryption using HMAC-256 keystream in cipher feedback mode
    key_byte_arr = bytearray(key)
    message_byte_arr = bytearray(message)
    # print(f"Length of ciphertext: {len(message_byte_arr)}")
    iv = hash_function(key)
    output = key_byte_arr
    decrypted = bytearray()
    prev_dec = iv
    for i in range(0, len(message_byte_arr), HASH_OUTPUT_SIZE):
        block = message_byte_arr[i:i+HASH_OUTPUT_SIZE]
        output = hmac(iv, prev_dec)
        dec = xor(block, output)
        prev_dec = block
        decrypted += dec
        # print(f"Block offset: {i}:\nciphertext: {block}\noutput: {output}\nplaintext: {dec}\n")
    # print(f"Length of decrypted value: {len(decrypted)}")
    return decrypted

if __name__ == "__main__":
    secret_key = random(32)
    # message = b"A" * 64
    message = b"Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Lacus sed viverra tellus in hac habitasse platea. Pulvinar pellentesque habitant morbi tristique senectus et netus. Aenean vel elit scelerisque mauris pellentesque. Iaculis eu non diam phasellus vestibulum lorem sed."
    print(f"Plaintext: {message}")
    print("*" * 20)
    enc = keyed_hash_encryption(secret_key, message)
    print(f"Encrypted: {enc}")
    print("*" * 20)
    dec = keyed_hash_decryption(secret_key, enc)
    print(f"Decrypted: {dec}")
