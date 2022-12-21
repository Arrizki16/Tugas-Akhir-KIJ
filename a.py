import socket
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization

HEADER = 1028
PORT = 8080
FORMAT = 'utf-8'
DISCONNECT_MESSAGE = '!DISCONNECT'
SERVER = '127.0.0.1'
ADDR = (SERVER, PORT)
ID_A = 100
PU_B = None
PR_B = None

client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.connect(ADDR)

def send(msg):
    message = msg.encode(FORMAT)
    msg_length = len(message)
    send_length = str(msg_length).encode(FORMAT)
    send_length += b' ' * (HEADER - len(send_length))
    client.send(send_length)

    # encrypt()
    
    client.send(message)
    print(client.recv(2048).decode(FORMAT))

def encrypt():
    # E (PUb, [N1||IDa])
    pass


if __name__ == '__main__':
    pass
