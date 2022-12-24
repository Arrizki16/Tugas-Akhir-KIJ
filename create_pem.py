from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

message = b'Public and Private keys encryption test'

PERSON = ['A', 'B']

def generateKey():
    for i in PERSON:
        pr = RSA.generate(1024)
        pu = pr.publickey()
        private_pem = pr.export_key().decode()
        public_pem = pu.export_key().decode()

        with open(f'private_key_{i}.pem', 'w') as pr:
            pr.write(private_pem)
        with open(f'public_key_{i}.pem', 'w') as pu:
            pu.write(public_pem)

        print("[SUCCESS] Creating keys is successfull")


def readKeyA():
    pr_key = RSA.import_key(open(f'private_key_A.pem', 'r').read())
    pu_key = RSA.import_key(open(f'public_key_A.pem', 'r').read())
    
    cipher = PKCS1_OAEP.new(key=pu_key)

    cipher_text = cipher.encrypt(message)
    decrypt = PKCS1_OAEP.new(key=pr_key)
    decrypted_message = decrypt.decrypt(cipher_text)
    
    return cipher_text, decrypted_message


def readKeyB():
    pr_key = RSA.import_key(open(f'private_key_B.pem', 'r').read())
    pu_key = RSA.import_key(open(f'public_key_B.pem', 'r').read())
    return pr_key, pu_key
    # cipher = PKCS1_OAEP.new(key=pu_key)

    # cipher_text = cipher.encrypt(message)
    # decrypt = PKCS1_OAEP.new(key=pr_key)
    # decrypted_message = decrypt.decrypt(cipher_text)
    
    # return cipher_text, decrypted_message


if __name__ == "__main__":
    generateKey()
    ct_a , et_a = readKeyA()
    ct_b , et_b = readKeyB()

    print(ct_a, et_a)
    print("---------")
    print(ct_b, et_b)