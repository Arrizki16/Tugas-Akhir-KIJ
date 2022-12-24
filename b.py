import socket, random, base64
from threading import Thread
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import load_der_public_key

HEADER = 1028
ADDR = ('127.0.0.1', 5050)
FORMAT = 'utf-8'
CONNECTIONS = dict()
PRIVATE_KEY = rsa.generate_private_key(65537, 2048)
PUBLIC_KEY = PRIVATE_KEY.public_key()
PUBLIC_KEY_A = None

def nonceGenerator():
	num = ""
	for i in range(10):
		rand = random.randint(0,1)
		num += str(rand)
	return num


def getAPublicKey(b_pem):
    b_pem = b_pem.decode("utf-8")
    b64data = '\n'.join(b_pem.splitlines()[1:-1])
    derdata = base64.b64decode(b64data)
    pua = load_der_public_key(derdata, default_backend())
    return pua


def getn1(encryptedMessage):
    cert_decrypted = b''
    cert_decrypted += PRIVATE_KEY.decrypt(
        encryptedMessage,
        padding.OAEP(
            mgf=padding.MGF1(hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    n1 = cert_decrypted[0:10].decode()
    return n1


# SENDING PUBLIC KEY TO A
def handle_client(conn, addr, client_id):
    print("[ACK]    Assigning ID", client_id, "to client ", addr[0], ":", addr[1])
    conn.send(CONNECTIONS[conn.getpeername()].encode())

    print("[SEND]   Sending public key to client", client_id)
    public_key_pem = PUBLIC_KEY.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
        # encoding=serialization.Encoding.PEM,
        # format=serialization.PrivateFormat.PKCS8,
        # encryption_algorithm=serialization.BestAvailableEncryption(password=b'Q&s&6Zxc2b&RUeBB')
    )
    conn.send(public_key_pem)

    encryptedMessage1 = conn.recv(2048)
    n1 = getn1(encryptedMessage1)
    n2 = nonceGenerator()
    print("n2 : ", n2)
    content = (n1 + n2).encode()

    a_pem = conn.recv(2048)
    PUBLIC_KEY_A = getAPublicKey(a_pem)

    encryptedMessage2 = PUBLIC_KEY_A.encrypt(
        content,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    conn.send(encryptedMessage2)


# START SERVER AND GO TO handle_client
def start():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(ADDR)

    print("[WAIT]   Waiting for connection...")
    server.listen(2)

    no_of_connection = 0

    while True:
        conn, addr = server.accept()
        new_id = None
        print("[ACK]    Incoming connection from: ", addr)

        if conn.getpeername() not in CONNECTIONS.keys():
            no_of_connection += 1
            new_id = str(no_of_connection).zfill(8)
            CONNECTIONS[conn.getpeername()] = new_id

        Thread(
            target=handle_client,
            args=(conn, addr, new_id)
        ).start()


if __name__ == '__main__':
    print("[START]  Server is starting...")
    start()