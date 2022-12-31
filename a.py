from hashlib import sha256
import os
import socket, random, sys, base64
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import load_der_public_key
from Cryptodome.Cipher import AES
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from Crypto.Cipher import AES

PORT = 5050
SERVER = '127.0.0.1'
ADDR = (SERVER, PORT)
ID = None
N1 = None

PRIVATE_KEY = rsa.generate_private_key(65537, 2048)
PUBLIC_KEY = PRIVATE_KEY.public_key()
PUBLIC_KEY_B = None


def print_menu_options():
    print("Options:")
    print("\t Enter 'connect' to connect to server")
    print("\t Enter 'quit' to exit")


def custom_private_key_encrypt(ks, key):
    if key is None:
        raise ValueError("No private key available")

    n = (PRIVATE_KEY.private_numbers().p)*(PRIVATE_KEY.private_numbers().q)
    if not 0 <= ks < n:
        raise ValueError("Message too large")
    return int(pow(ks, key.private_numbers().d , n))


def random_10_bit():
	num = ""
	for i in range(10):
		rand = random.randint(0,1)
		num += str(rand)
	return int(num,2)


def nonce_generator():
	num = ""
	for i in range(10):
		rand = random.randint(0,1)
		num += str(rand)
	return num


def get_b_public_key(b_pem):
    b_pem = b_pem.decode("utf-8")
    b64data = '\n'.join(b_pem.splitlines()[1:-1])
    derdata = base64.b64decode(b64data)
    pub = load_der_public_key(derdata, default_backend())

    return pub


def get_n2(encryptedMessage):
    decrypted_message = b''
    decrypted_message += PRIVATE_KEY.decrypt(
        encryptedMessage,
        padding.OAEP(
            mgf=padding.MGF1(hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    n2 = decrypted_message[10:].decode()
    return n2


if __name__ == '__main__':
    conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        conn.connect(ADDR)
    except:
        print("Connection error")
        sys.exit()
    
    ID = conn.recv(2048).decode()

    while True:
        print_menu_options()
        message = input(" -> ")
        conn.send(message.encode())

        if 'connect' in message :
            # STEP 1
            b_pem = conn.recv(2048)
            PUBLIC_KEY_B = get_b_public_key(b_pem)
            N1 = nonce_generator()
            content = (N1 + ID).encode()

            encryptedMessage = PUBLIC_KEY_B.encrypt(
                content,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            conn.send(encryptedMessage)
            
            # STEP 2
            pua = PUBLIC_KEY.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            conn.send(pua)

            # STEP 3
            encryptedMessage2 = conn.recv(2048)
            n2 = get_n2(encryptedMessage2).encode()

            encryptedMessage3 = PUBLIC_KEY_B.encrypt(
                n2,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            conn.send(encryptedMessage3)

            # STEP 4
            ks = random.randint(0, 2**256 - 1)
            if conn.recv(2048).decode() == 'VERIFIED' :
                ks_encrypted = custom_private_key_encrypt(ks, PRIVATE_KEY)
                ks_encrypted = ks_encrypted.to_bytes(256, 'big')

                ### implementasi symetric
                key = os.urandom(AES.block_size)
                iv = os.urandom(AES.block_size)
                cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
                encryptor = cipher.encryptor()
                ct = encryptor.update(ks_encrypted) + encryptor.finalize()
                ###

                key_message = PUBLIC_KEY_B.encrypt(
                    key,
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )
                iv_message = PUBLIC_KEY_B.encrypt(
                    iv,
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )

                conn.send(ct)
                combined_message = b''.join([key_message,iv_message])
                conn.send(combined_message)

            else :
                break

        elif 'quit' in message :
            break