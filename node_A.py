import zmq
from Crypto.Cipher import AES

context = zmq.Context()
socket = context.socket(zmq.REP)
socket.bind("tcp://*:5555")

iv = b"abcdefghijklmnop"
key1 = b"abcdcbabcdcbabcd"


def choose_mode():
    choose = int(input("What mode do you want? \n 1.ECB \n 2.OFB\n"))
    if choose == 1:
        return "ECB"
    else:
        return "OFB"


def decrypt_aes(key_encrypted):
    cipher_aes = AES.new(key1, AES.MODE_ECB)
    return cipher_aes.decrypt(key_encrypted)


def check_plaintext(plain):
    while len(plain) % 16 != 0:
        plain += " "
    return plain


def xor(x, y):
    return bytes(a ^ b for (a, b) in zip(x, y))


def send_encrypted_message():
    with open("msg.txt", "r") as fp:
        plaintext = fp.read()

    plaintext = check_plaintext(plaintext)
    key_decrypted = decrypt_aes(key)
    cipher_aes = AES.new(key_decrypted, AES.MODE_ECB)
    crypto_text = b""
    blocks = []
    for i in range(0, int(len(plaintext) / 16)):
        blocks.append(plaintext[i * 16:(i * 16 + 16)])
    if mode == "ECB":
        for block in blocks:
            crypto_text += cipher_aes.encrypt(block.encode())
    elif mode == "OFB":
        for block in blocks:
            global iv
            encrypted_iv = cipher_aes.encrypt(iv)
            crypto_text += xor(encrypted_iv, block.encode())
            iv = encrypted_iv
    return crypto_text


key = b""
mode = choose_mode()

while True:

    message = socket.recv_string()
    action, arg = message.split(":", 1)

    if action == "key":
        socket.send_string("send_to_me:")
        key = socket.recv()
        socket.send_string("ok")

    elif action == "bnode":
        socket.send_string("mode:" + mode)

    elif action == "send_key":

        if len(key) > 1:
            socket.send(key)

    elif action == "can_start":
        socket.send(send_encrypted_message())
        socket.recv_string()
        break
