import socket, random, base64, traceback
from threading import Thread
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import load_der_public_key
from Cryptodome.Cipher import AES
from Cryptodome.Hash import SHA256


ADDR = ('127.0.0.1', 5050)
FORMAT = 'utf-8'
CONNECTIONS = dict()
PRIVATE_KEY = rsa.generate_private_key(65537, 2048)
PUBLIC_KEY = PRIVATE_KEY.public_key()
PUBLIC_KEY_A = None
N2 = None


def nonceGenerator():
	num = ""
	for i in range(10):
		rand = random.randint(0,1)
		num += str(rand)
	return num


def receive_input(conn):
    client_input = conn.recv(2048)
    client_input = client_input.decode().rstrip()
    return client_input


def getAPublicKey(b_pem):
    b_pem = b_pem.decode("utf-8")
    b64data = '\n'.join(b_pem.splitlines()[1:-1])
    derdata = base64.b64decode(b64data)
    pua = load_der_public_key(derdata, default_backend())
    return pua


def customPUdecrypt(ks, key):
    if key is None:
        raise ValueError("No public key available")
    if not 0 <= ks <= key.public_numbers().n:
        raise ValueError("Message too large")
    return int(pow(ks, key.public_numbers().e, key.public_numbers().n))


def getn1(encryptedMessage):
    decrypted_message = b''
    decrypted_message += PRIVATE_KEY.decrypt(
        encryptedMessage,
        padding.OAEP(
            mgf=padding.MGF1(hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    n1 = decrypted_message[0:10].decode()
    return n1


def getN2fromA(encryptedMessage3):
    decrypted_message = b''
    decrypted_message += PRIVATE_KEY.decrypt(
        encryptedMessage3,
        padding.OAEP(
            mgf=padding.MGF1(hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    n2 = decrypted_message[0:10].decode()
    return n2


def handle_client(conn, addr, client_id):
    print("[ACK]    Assigning ID", client_id, "to ", addr[0], ":", addr[1])
    conn.send(CONNECTIONS[conn.getpeername()].encode())

    print("[SEND]   Sending public key to ", client_id)
    public_key_pem = PUBLIC_KEY.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    conn.send(public_key_pem)

    while True:
        client_input = receive_input(conn)
        if "quit" in client_input:
            CONNECTIONS[conn.getpeername()] = None
            conn.close()
            print("[DISC]   Client", client_id, "disconnected.")
            break

        elif "connect" in client_input:
            encryptedMessage1 = conn.recv(2048)
            n1 = getn1(encryptedMessage1)
            N2 = nonceGenerator()
            content = (n1 + N2).encode()

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
            print("[SEND]   Sending encrypted message to ", client_id)
            conn.send(encryptedMessage2)

            encryptedMessage3 = conn.recv(2048)
            n2_from_client = getN2fromA(encryptedMessage3)

            if n2_from_client == N2:
                print("[SUCCESS]    Authentication is successful")
                conn.send("VERIFIED".encode())

                finalEncryptedMessage = conn.recv(4096)
                aes_key_message = finalEncryptedMessage[256:]
                print(aes_key_message, len(aes_key_message))
                ks_message = finalEncryptedMessage[:256]
                print(ks_message, len(ks_message))
                
                aes_key_decrypt = PRIVATE_KEY.decrypt(
                    aes_key_message,
                    padding.OAEP(
                        mgf=padding.MGF1(hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )
                print(aes_key_decrypt, len(aes_key_decrypt))

                cipher = AES.new(aes_key_decrypt, AES.MODE_CBC)

                aes_plaintext = cipher.decrypt(ks_message)

                print("AES Plaintext : ", aes_plaintext, len(aes_plaintext))

                ks = customPUdecrypt(int.from_bytes(aes_plaintext, 'big'), PUBLIC_KEY_A)
                print("KS : ", ks)

                # decrypted_string = bytes(ks).decode()
                # print(decrypted_string)


            else :
                print("[FAILED]     Authentication fails")
                conn.close()
        else:
            pass


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
        try:
            Thread(
                target=handle_client, 
                args=(conn, addr, new_id)
            ).start()
        except:
            print("Thread did not start.")
            traceback.print_exc()


if __name__ == '__main__':
    print("[START]  Server is starting...")
    start()