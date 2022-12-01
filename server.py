#!/usr/bin/env python3
import argparse
import socket
import threading
from collections import defaultdict

from nacl.encoding import HexEncoder
from nacl.public import Box, PrivateKey, PublicKey
from nacl.signing import SigningKey, VerifyKey
from nacl.utils import random

from config import CLIENT_PORT, HOST, MAX_USERNAME_LEN, SESSION_KEY_SIZE, SIGNATURE_SIZE, MAX_DATA_SIZE
from utility import decrypt_and_verify, server_port, encrypt_and_sign, verify, get_hash_signature_message


class Server:
    def __init__(self, host, port):
        # key used to decrypt messages
        self.private_key = PrivateKey(
            open("./key_pairs/server", encoding="utf-8").read(), HexEncoder
        )
        # key used to sign messages
        self.signing_key = SigningKey(
            open("./key_pairs/server_dsa", encoding="utf-8").read(), HexEncoder
        )
        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.s.bind((host, port))
        self.clients = defaultdict(str)

    def start(self):
        print("Waiting for connection")
        self.s.listen()

        while True:
            conn, addr = self.s.accept()
            args = (conn, addr)
            threading.Thread(target=self.connect_client, args=args).start()
    
    def connect_client(self, conn, addr):
        client_user_bytes = conn.recv(MAX_USERNAME_LEN)
        client_user = client_user_bytes.decode()
        print(f"Received connection request from client {client_user}")

        # key used to encrypt messages for the client
        client_public_key = PublicKey(
            open(f"./key_pairs/{client_user}.pub", encoding="utf-8").read(), HexEncoder
        )
        # key used to verify messages from the client
        verify_key = VerifyKey(
            open(f"./key_pairs/{client_user}_dsa.pub", encoding="utf-8").read(), HexEncoder
        )

        box = Box(self.private_key, client_public_key)

        # 24 bytes
        nonce = random(Box.NONCE_SIZE)

        # challenge
        message = encrypt_and_sign(nonce, box, self.signing_key)
        print(len(message))
        print("Sending challenge to client")
        conn.send(message)

        # response
        message = conn.recv(MAX_DATA_SIZE)
        print("Received response from client")
        hashed_message, signature, decrypted_nonce = get_hash_signature_message(message)

        verify(decrypted_nonce, hashed_message, signature, verify_key)
        if nonce == decrypted_nonce:
            print(f"Client {client_user} authenticated successfully")
        else:
            print(f"Failed login from client {client_user}")
            conn.close()

        self.clients[client_user] = addr[0]

        # session key
        self.send_key(box, conn)

        clients = self.get_clients()
        print(f"List of available clients: {clients}")
        message = b"\n".join(clients)
        print("clients:", clients)
        conn.send(message)

        user = None
        while user not in self.clients:
            enc = conn.recv(MAX_DATA_SIZE)
            user = decrypt_and_verify(enc, box, verify_key)
            user = user.decode()

        ip = self.clients[user]
        port = CLIENT_PORT

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((ip, port))
        self.send_key(box, sock)

        # conn.close()

    def send_key(self, box, socket):
        session_key = random(SESSION_KEY_SIZE)
        signed_message = encrypt_and_sign(session_key, box, self.signing_key)
        socket.send(signed_message)

    def get_clients(self):
        return [bytes(f"{name}:{addr}", "utf-8") for name, addr in self.clients.items()]

    def die(self):
        print("dying")
        self.s.shutdown(1)
        self.s.close()


def main():
    parser = argparse.ArgumentParser("Client application")
    parser.add_argument(
        "--port", type=server_port, default=8000, help="Port to run server on"
    )
    args = parser.parse_args()

    s = Server(HOST, args.port)
    s.start()
    s.die()


if __name__ == "__main__":
    main()
