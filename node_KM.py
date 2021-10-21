import random
import zmq
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

context = zmq.Context()
socket = context.socket(zmq.REQ)
socket.connect("tcp://localhost:5555")

iv = b"abcdefghijklmnop"
key1 = b"abcdcbabcdcbabcd"

key = get_random_bytes(16)


def encrypt_key(key_to_encrypt):
    cipher = AES.new(key1, AES.MODE_ECB)
    return cipher.encrypt(key_to_encrypt)


def sendKey():
    socket.send_string("key:")
    message = socket.recv_string()
    action, arg = message.split(":", 1)
    if action == "send_to_me":
        socket.send(key_encrypted)
        socket.recv()


key_encrypted = encrypt_key(key)
sendKey()
