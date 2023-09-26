from cryptography.hazmat.primitives import (
    serialization, hashes)
import logging
from cryptography.hazmat.primitives.asymmetric import (
    rsa, padding as as_padding)
import warnings
from cryptography.utils import CryptographyDeprecationWarning

warnings.filterwarnings("ignore", category=CryptographyDeprecationWarning)

def keys(sym_key: bytes) -> bytes:
    """

    Функция для ассиметричного шифрования.

    :return: ключ
    """
    file_settings = {
        'initial_file': "files/initial_file.txt",
        'encrypted_file': "files/encrypted_file.txt",
        'decrypted_file': "files/decrypted_file.txt",
        'symmetric_key': "files/symmetric_key.txt",
        'public_key': "files/public_key.txt",
        'private_key': "files/private_key.txt",
        'encrypted_vector': "files/encrypted_vector.txt"
    }

    assym_keys = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    private_key = assym_keys
    public_key = assym_keys.public_key()

    c_key = public_key.encrypt(
        sym_key,
        as_padding.OAEP(
            mgf=as_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(), label=None))
    try:
        with open(file_settings['public_key'], 'wb') as public_out:
            public_out.write(
                public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo))
    except IOError:
        logging.error(f"Ошибка: В файле {file_settings['public_key']}")

    try:
        with open(file_settings['private_key'], 'wb') as private_out:
            private_out.write(
                private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                    encryption_algorithm=serialization.NoEncryption()))
    except IOError:
        logging.error(f"Ошибка: В файле {file_settings['private_key']}")

    return c_key
