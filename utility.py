import argparse
from config import SIGNATURE_SIZE
from nacl.exceptions import BadSignatureError
from nacl.hash import sha256

MIN_PORT = 0
MAX_PORT = 65535

def allowed_ports(port):
    int_port = int(port)
    if MIN_PORT <= int_port <= MAX_PORT:
        return int_port 
    raise argparse.ArgumentTypeError(f"{MIN_PORT} <= port <= {MAX_PORT}")

def sign_hash(message, signing_key, hash_function=sha256):
    hashed_message = hash_function(message)
    print(f"Hashed message: {hashed_message} of length {len(hashed_message)}")
    signed_message = signing_key.sign(hashed_message)
    return signed_message

def encrypt_and_sign(message, box, signing_key, hash_function=sha256):
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
