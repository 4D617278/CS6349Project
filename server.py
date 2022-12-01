#!/usr/bin/env python3
import argparse
import socket
import threading
from collections import defaultdict

from nacl.encoding import HexEncoder
from nacl.public import Box, PrivateKey, PublicKey
from nacl.signing import SigningKey, VerifyKey
from nacl.utils import random

from config import HOST, MAX_USERNAME_LEN, SESSION_KEY_SIZE, SIGNATURE_SIZE, MAX_DATA_SIZE
from utility import mac_send, recv_decrypt, recv_verify, server_port, verify


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
        mac_send(conn, nonce, box, self.signing_key)

        # response
        decrypted_nonce = recv_verify(conn, verify_key)

        if nonce == decrypted_nonce:
            print(f"Client {client_user} authenticated successfully")
        else:
            print(f"Failed login from client {client_user}")
            conn.close()

        # ip:port
        session_key = random(SESSION_KEY_SIZE)
        self.clients[client_user] = f"{addr[0]}:{addr[1]}:{session_key}"

        while True:
            cmd = recv_decrypt(conn, box, verify_key).decode()

            match cmd:
                case 'g':
                    # client list
                    msg = b"\n".join(self.get_clients())
                    mac_send(conn, msg, box, self.signing_key)

                case _:
                    # peer
                    user = cmd

                    if user not in self.clients:
                        continue

                    ip, port, key = self.clients[user].split(':')

                    # session key
                    self.send_key(box, conn)

        conn.close()

    def send_key(self, box, socket):
        mac_send(socket, session_key, box, self.signing_key)

    def get_clients(self):
        return [bytes(f"{name}:{val}", "utf-8") for name, val in self.clients.items()]

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
