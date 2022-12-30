from hashlib import sha256
import os
import socket, random, sys, base64
from Crypto.Cipher import PKCS1_OAEP
from Cryptodome.Hash import SHA256
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import load_der_public_key
from Cryptodome.Cipher import AES
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from Crypto.Cipher import AES
from Crypto import Random


PORT = 5050
DISCONNECT_MESSAGE = '!DISCONNECT'
SERVER = '127.0.0.1'
ADDR = (SERVER, PORT)
ID = None
N1 = None

PRIVATE_KEY = rsa.generate_private_key(65537, 2048)
PUBLIC_KEY = PRIVATE_KEY.public_key()
PUBLIC_KEY_B = None


def printMenuOptions():
    print("Options:")
    print("\t Enter 'connect' to connect to server")
    print("\t Enter 'quit' to exit")


def customPRencrypt(ks, key):
    if key is None:
        raise ValueError("No private key available")

    n = (key.private_numbers().p - 1)*(key.private_numbers().q - 1)
    if not 0 <= ks < n:
        raise ValueError("Message too large")
    return int(pow(ks, key.private_numbers().d , n))


def random10bit():
	num = ""
	for i in range(10):
		rand = random.randint(0,1)
		num += str(rand)
	return int(num,2)


def nonceGenerator():
	num = ""
	for i in range(10):
		rand = random.randint(0,1)
		num += str(rand)
	return num


def getBPulbicKey(b_pem):
    b_pem = b_pem.decode("utf-8")
    b64data = '\n'.join(b_pem.splitlines()[1:-1])
    derdata = base64.b64decode(b64data)
    pub = load_der_public_key(derdata, default_backend())

    return pub


def getn2(encryptedMessage):
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
        printMenuOptions()
        message = input(" -> ")
        conn.send(message.encode())

        if 'connect' in message :
            # STEP 1
            b_pem = conn.recv(2048)
            PUBLIC_KEY_B = getBPulbicKey(b_pem)
            N1 = nonceGenerator()
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
            n2 = getn2(encryptedMessage2).encode()

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
            ks = nonceGenerator().encode()
            print("KS to byts : ", int.from_bytes(ks, 'big'))
            if conn.recv(2048).decode() == 'VERIFIED' :
                ks_encrypted = customPRencrypt(int.from_bytes(ks, 'big'), PRIVATE_KEY)
                print("KS AWAL : ", ks_encrypted)
                ks_encrypted = ks_encrypted.to_bytes(256, 'big')
                print("KS ENCRYPTED : ", ks_encrypted)

                ### implementasi symetric
                key = os.urandom(AES.block_size)
                print("\nkey asli : ", key)
                iv = os.urandom(AES.block_size)
                print("\niv asli : ", iv)
                cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
                encryptor = cipher.encryptor()
                ct = encryptor.update(ks_encrypted) + encryptor.finalize()
                print("\nCT : ", ct, len(ct))
                ###

                key_message = PUBLIC_KEY_B.encrypt(
                    key,
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )
                print("\nkey message : ", key_message)
                iv_message = PUBLIC_KEY_B.encrypt(
                    iv,
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )
                print("\niv message : ", iv_message)
                # print("FINAL ENCRYPTED : ", finalEncryptedMessage)
                conn.send(ct)
                combined_message = b''.join([key_message,iv_message])
                conn.send(combined_message)

            else :
                break

        elif 'quit' in message :
            break