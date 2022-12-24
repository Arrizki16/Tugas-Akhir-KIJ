import socket 
from threading import Thread
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization

HEADER = 1028
ADDR = ('127.0.0.1', 5050)
FORMAT = 'utf-8'
CONNECTIONS = dict()
PRIVATE_KEY = rsa.generate_private_key(65537, 2048)
PUBLIC_KEY = PRIVATE_KEY.public_key()


# SENDING PUBLIC KEY TO A
def handle_client(conn, addr, client_id):
    print("Assigning ID", client_id, "to client ", addr[0], ":", addr[1])
    conn.send(CONNECTIONS[conn.getpeername()].encode())

    print("Sending public key to client", client_id)
    public_key_pem = PUBLIC_KEY.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
        # encoding=serialization.Encoding.PEM,
        # format=serialization.PrivateFormat.PKCS8,
        # encryption_algorithm=serialization.BestAvailableEncryption(password=b'Q&s&6Zxc2b&RUeBB')
    )
    conn.send(public_key_pem)


    # decryptedMessage = conn.recv(2048)
    # print(decryptedMessage)



        

# START SERVER AND GO TO handle_client
def start():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(ADDR)

    print("Waiting for connection...")
    server.listen(2)

    no_of_connection = 0

    while True:
        conn, addr = server.accept()
        new_id = None
        print("Incoming connection from: ", addr)

        if conn.getpeername() not in CONNECTIONS.keys():
            no_of_connection += 1
            new_id = str(no_of_connection).zfill(8)
            CONNECTIONS[conn.getpeername()] = new_id

        Thread(
            target=handle_client,
            args=(conn, addr, new_id)
        ).start()


if __name__ == '__main__':
    print("[STARTING] server is starting...")
    start()