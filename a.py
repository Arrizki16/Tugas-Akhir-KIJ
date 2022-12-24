import socket, random, sys, base64
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import load_der_public_key

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
    print("\t Enter 'quit' to exit")
    print("\t Enter 'connect' to connect to server")


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
    cert_decrypted = b''
    cert_decrypted += PRIVATE_KEY.decrypt(
        encryptedMessage,
        padding.OAEP(
            mgf=padding.MGF1(hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    n2 = cert_decrypted[10:].decode()
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

            encryptedMessage2 = conn.recv(2048)

            # STEP 3
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

        elif 'quit' in message :
            break