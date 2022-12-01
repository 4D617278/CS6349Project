import argparse

from nacl.hash import sha256
from nacl.utils import random
from nacl.encoding import RawEncoder
from nacl.signing import SignedMessage

from config import SIGNATURE_SIZE, HASH_OUTPUT_SIZE, MAX_DATA_SIZE

MIN_SERVER_PORT = 0
MAX_SERVER_PORT = 32767
MIN_CLIENT_PORT = 32768
MAX_CLIENT_PORT = 65535

def raw_sha256(message):
    # Return the output of sha256 in bytes
    return sha256(message, encoder=RawEncoder)

def client_port(port):
    port = int(port)
    if MIN_CLIENT_PORT <= port <= MAX_CLIENT_PORT:
        return port 
    raise argparse.ArgumentTypeError(f"{MIN_CLIENT_PORT} <= port <= {MAX_CLIENT_PORT}")

def server_port(port):
    port = int(port)
    if MIN_SERVER_PORT <= port <= MAX_SERVER_PORT:
        return port 
    raise argparse.ArgumentTypeError(f"{MIN_SERVER_PORT} <= port <= {MAX_SERVER_PORT}")


def sign_hash(message, signing_key, hash_function=raw_sha256):
    """Hash a message using hash_function and sign it using signing_key"""
    hashed_message = hash_function(message)
    print(f"Hashed message: {hashed_message} of length {len(hashed_message)}")
    signed_hash = signing_key.sign(hashed_message)
    return signed_hash.message, signed_hash.signature


def encrypt_and_sign(message, box, signing_key, hash_function=raw_sha256):
    """Encrypt a message using box and sign it using signing_key"""
    print(f"Original message: {message} of length {len(message)}")
    encrypted_message = box.encrypt(message)
    print(f"Encrypted message: {encrypted_message} of length {len(encrypted_message)}")
    hashed_message, signature = sign_hash(encrypted_message, signing_key, hash_function)
    print(f"Signature: {signature} of length {len(signature)}")
    return hashed_message + signature + encrypted_message


def mac(msg, sym_key, hash_function=raw_sha256):
    enc = keyed_hash_encryption(sym_key, msg)
    hash = hash_function(enc)
    mac = keyed_hash_encryption(sym_key, hash)
    return mac + enc


def get_hash_signature_message(message):
    """Split the message into the signed hash and the encrypted message"""
    hashed_message, signature, encrypted_message = (
        message[:HASH_OUTPUT_SIZE],
        message[HASH_OUTPUT_SIZE:SIGNATURE_SIZE],
        message[SIGNATURE_SIZE:],
    )
    return hashed_message, signature, encrypted_message


def verify(message, hashed_message, signature, verify_key, hash_function=raw_sha256):
    print(f"Hashed message: {hashed_message}")
    print(f"Current hash: {hash_function(message)}")
    assert hashed_message == hash_function(message)
    verify_key.verify(hashed_message, signature)


def verify_dec(msg, sym_key, hash_function=raw_sha256):
    hash = keyed_hash_decryption(sym_key, msg[:HASH_OUTPUT_SIZE])
    enc = msg[HASH_OUTPUT_SIZE:]
    assert hash == hash_function(enc)
    msg = keyed_hash_decryption(sym_key, enc)
    return msg


def decrypt_and_verify(message, box, verify_key, hash_function=raw_sha256):
    """Decrypt the message using box and verify the hash using verify_key"""
    hashed_message, signature, encrypted_message = get_hash_signature_message(message)
    print(f"Encrypted message: {encrypted_message} of length {len(encrypted_message)}")
    verify(encrypted_message, hashed_message, signature, verify_key)
    decrypted_message = box.decrypt(encrypted_message)
    print(f"Decrypted message: {decrypted_message} of length {len(decrypted_message)}")
    return decrypted_message


def mac_send(sock, msg, key, box=None):
    if box:
        enc = encrypt_and_sign(msg, box, key)
    else:
        enc = mac(msg, key)
        print(f'Enc: {enc}')
    sock.send(enc)


def recv_dec(sock, key, box=None):
    msg = sock.recv(MAX_DATA_SIZE)
    print(f'Msg: {msg}')
    if box:
        return decrypt_and_verify(msg, box, key)
    else:
        return verify_dec(msg, key)


def recv_verify(sock, verify_key):
    msg = sock.recv(MAX_DATA_SIZE)
    hash, signature, msg = get_hash_signature_message(msg)
    verify(msg, hash, signature, verify_key)
    return msg


def sign_send(sock, msg, sign_key):
    hash, signature = sign_hash(msg, sign_key)
    sock.send(hash + signature + msg)


def xor(bytes1, bytes2):
    """XOR two byte arrays"""
    return bytes(x ^ y for (x, y) in zip(bytes1, bytes2))


def pad(data, block_size=64):
    """Pad key with 0's until block_size"""
    #padding = bytearray(block_size - len(key))
    padding = bytearray(block_size - len(data) % block_size)
    return data + padding


def compute_block_sized_key(key, block_size=HASH_OUTPUT_SIZE, hash_function=raw_sha256):
    """Convert key into a key of size block_size"""
    if len(key) > block_size:
        key = hash_function(key)
    if len(key) < block_size:
        return pad(key, block_size)
    return key


def hmac(key, message, block_size=HASH_OUTPUT_SIZE, hash_function=raw_sha256):
    """https://en.wikipedia.org/wiki/HMAC#Implementation"""
    block_sized_key = compute_block_sized_key(key)
    opad = b"\x5c" * block_size
    ipad = b"\x36" * block_size
    o_key_pad = xor(block_sized_key, opad)
    i_key_pad = xor(block_sized_key, ipad)
    return hash_function(o_key_pad + hash_function(i_key_pad + message))


def keyed_hash_encryption(
    key, message, block_size=HASH_OUTPUT_SIZE, hash_function=raw_sha256
):
    """Encryption using HMAC-256 keystream in cipher feedback mode"""
    key_byte_arr = bytearray(key)
    message_byte_arr = bytearray(message)
    # TODO: use nonce
    iv = hash_function(key)
    output = key_byte_arr
    encrypted = bytearray()
    prev_enc = iv

    # TODO: pad the message to a multiple of block_size
    #message_byte_arr = pad(message_byte_arr)

    for i in range(0, len(message_byte_arr), HASH_OUTPUT_SIZE):
        block = message_byte_arr[i : i + HASH_OUTPUT_SIZE]
        # O(i) = HMAC(IV, C(i-1))
        output = hmac(iv, prev_enc)
        # C(i) = P(i) ^ O(i)
        enc = xor(block, output)
        prev_enc = enc
        encrypted += enc
    return bytes(encrypted)


def keyed_hash_decryption(
    key, message, block_size=HASH_OUTPUT_SIZE, hash_function=raw_sha256
):
    """Decryption using HMAC-256 keystream in cipher feedback mode"""
    #return keyed_hash_encryption(key, message)
    key_byte_arr = bytearray(key)
    message_byte_arr = bytearray(message)
    # TODO: use nonce
    iv = hash_function(key)
    output = key_byte_arr
    decrypted = bytearray()
    prev_dec = iv

    for i in range(0, len(message_byte_arr), HASH_OUTPUT_SIZE):
        block = message_byte_arr[i : i + HASH_OUTPUT_SIZE]
        # O(i) = HMAC(IV, P(i-1))
        output = hmac(iv, prev_dec)
        # P(i) = C(i) ^ O(i)
        dec = xor(block, output)
        prev_dec = block
        decrypted += dec
    return bytes(decrypted)


if __name__ == "__main__":
    secret_key = random(32)
    # message = b"A" * 64
    message = random(int.from_bytes(random(1), 'little'))
    print(f"Plaintext: {message}")
    print("*" * 20)
    enc = keyed_hash_encryption(secret_key, message)
    print(f"Encrypted: {enc}")
    print("*" * 20)
    dec = keyed_hash_decryption(secret_key, enc)
    print(f"Decrypted: {dec}")

    if (message == dec):
        print('Good')
