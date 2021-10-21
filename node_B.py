import zmq
from Crypto.Cipher import AES

context = zmq.Context()
socket = context.socket(zmq.REQ)
socket.connect("tcp://localhost:5555")

IV = b"abcdefghijklmnop"
key1 = b"abcdcbabcdcbabcd"
mode = ""


def decrypt_aes(key_encrypted):
    cipher_aes = AES.new(key1, AES.MODE_ECB)
    return cipher_aes.decrypt(key_encrypted)
def xor(x ,y):
    return bytes(a ^ b for (a, b) in zip(x, y))

def decrypt_text(cipher_text, encrypted_key, mode, iv):
    key_decrypted = decrypt_aes(encrypted_key)
    cipher_aes = AES.new(key_decrypted, AES.MODE_ECB)
    crypto_text = b""
    blocks = []
    for i in range(0, int(len(cipher_text) / 16)):
        blocks.append(cipher_text[i * 16:(i * 16 + 16)])
    if mode == "ECB":
        for block in blocks:
            crypto_text += cipher_aes.decrypt(block)
    elif mode == "OFB":
        for block in blocks:
            encrypted_iv = cipher_aes.encrypt(iv)
            crypto_text += xor(encrypted_iv,block)
            iv = encrypted_iv
    return crypto_text
def writeToFile(decrypted):
    with open("decrypted.txt","w") as fp :
        fp.write(decrypted.decode('UTF-8'))


socket.send_string("bnode:aa")

message = socket.recv_string()

action, arg = message.split(":", 1)
if action == "mode":
    mode = arg

socket.send_string("send_key:")

key = socket.recv()

socket.send_string("can_start:")
encrypted_text = socket.recv()
socket.send_string("ok")

decr_text=decrypt_text(encrypted_text,key,mode,IV)
print(decr_text)
writeToFile(decr_text)

