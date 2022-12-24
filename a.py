import socket, random, sys, base64
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import load_der_public_key

HEADER = 1028
PORT = 5050 
FORMAT = 'utf-8'
DISCONNECT_MESSAGE = '!DISCONNECT'
SERVER = '127.0.0.1'
ADDR = (SERVER, PORT)
ID = None

PUBLIC_KEY = rsa.generate_private_key(65537, 2048)
PRIVATE_KEY = PUBLIC_KEY.public_key()
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

# def send(msg):
#     message = msg.encode(FORMAT)
#     msg_length = len(message)
#     send_length = str(msg_length).encode(FORMAT)
#     send_length += b' ' * (HEADER - len(send_length))
#     client.send(send_length)

#     # encrypt()
    
#     client.send(message)
#     print(client.recv(2048).decode(FORMAT))

# def sendEncryptedMessage():
#     pass


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
            # pua = PUBLIC_KEY.public_bytes(
            #     encoding=serialization.Encoding.PEM,
            #     format=serialization.PublicFormat.SubjectPublicKeyInfo
            # )
            # print(pua)
            # conn.send(pua)

            b_pem = conn.recv(2048)
            b_pem = b_pem.decode("utf-8")
            b64data = '\n'.join(b_pem.splitlines()[1:-1])
            derdata = base64.b64decode(b64data)
            PUBLIC_KEY_B = load_der_public_key(derdata, default_backend())

            print(PUBLIC_KEY)
            

            n1 = nonceGenerator()
            content = (n1 + ID).encode()

            encryptedMessage = PUBLIC_KEY_B.encrypt(
                content,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )

            conn.send(encryptedMessage)

            

            print("PRIVATE KEY : ", PRIVATE_KEY)
            print("PUBLIC KEY : ", PUBLIC_KEY)


