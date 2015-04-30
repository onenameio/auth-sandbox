import json
import base64
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization


def generate_keypair(public_exponent, key_size):
    private_key = rsa.generate_private_key(
        public_exponent=public_exponent,
        key_size=key_size,
        backend=default_backend())
    public_key = private_key.public_key()
    return private_key, public_key


def serialize_public_key_to_der(public_key):
    public_key_der = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo)
    return public_key_der


def serialize_private_key_to_pem(private_key):
    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption())
    return private_key_pem


def serialize_public_key_to_pem(public_key):
    public_key_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo)
    return public_key_pem


def jsonify_pems(private_key_pem, public_key_pem):
    data = json.dumps({
        'private': private_key_pem,
        'public': public_key_pem
    })
    return data


def encrypt_private_key(private_key, encryption_key):
    private_key_pem_encrypted = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(
            encryption_key))
    return private_key_pem_encrypted


def main():
    RSA_PUBLIC_EXPONENT = 65537
    RSA_KEY_SIZE = 2048
    encryption_key = b'3394e9a31ff0f0be3e55bab7e20057e013e47768f075c3d7'

    private_key, public_key = generate_keypair(
        RSA_PUBLIC_EXPONENT, RSA_KEY_SIZE)

    public_key_der = serialize_public_key_to_der(public_key)

    print base64.b64encode(public_key_der)

    # private_key_pem = serialize_private_key_to_pem(private_key)
    public_key_pem = serialize_public_key_to_pem(public_key)

    # print private_key_pem
    print public_key_pem

    # json_pems = jsonify_pems(private_key_pem, public_key_pem)

    # print json_pems + '\n'

    # private_key_pem_encrypted = encrypt_private_key(
    #    private_key, encryption_key)

    # print private_key_pem_encrypted


if __name__ == '__main__':
    main()
