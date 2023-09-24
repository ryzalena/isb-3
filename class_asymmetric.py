import logging

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import load_pem_public_key, load_pem_private_key
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes

import warnings
from cryptography.utils import CryptographyDeprecationWarning

warnings.filterwarnings("ignore", category=CryptographyDeprecationWarning)

class Asymmetric():
    def generate_pair_of_keys() -> tuple:
        """
        Функция создания ключей для асимметричного шифрования.

        :return: ключ.
        """
        keys = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        private_key = keys
        public_key = keys.public_key()
        logging.output('Ключи асимметричного шифрования успешно созданы.')

        return private_key, public_key
,

    def asymmetric_encrypt(public_key, text: bytes) -> bytes:
        """
        Функция шифрования текста с помощью асимметричного алгоритма кодирования.

        :return: Зашифрованный текст.
        """
        c_text = public_key.encrypt(text,
                                    padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(),
                                                 label=None))
        logging.output('Текст зашифрован')

        return c_text


    def asymmetric_decrypt(private_key, text: bytes) -> bytes:
        """
        Функция расшифровки текста

        :return: Расшифрованный текст
        """
        dc_text = private_key.decrypt(text,
                                      padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                                   algorithm=hashes.SHA256(),
                                                   label=None))
        logging.output('Текст расшифрован, соответсвующий файл создан.')
        return dc_text


    def serialize_asymmetric_keys(public_key, private_key, public_pem: str, private_pem: str) -> None:
        """
        Функция сериализации ключей асимметричного алгоритма шифрования.

        :return: ничего.
        """
        try:
            with open(public_pem, 'wb') as public_out:
                public_out.write(public_key.public_bytes(encoding=serialization.Encoding.PEM,
                                                         format=serialization.PublicFormat.SubjectPublicKeyInfo))
                logging.info('Публичный ключ сериализован.')
            with open(private_pem, 'wb') as private_out:
                private_out.write(private_key.private_bytes(encoding=serialization.Encoding.PEM,
                                                            format=serialization.PrivateFormat.TraditionalOpenSSL,
                                                            encryption_algorithm=serialization.NoEncryption()))
                logging.info('Приватный ключ сериализован.')
        except OSError as err:
            logging.warning(f'{err} Не удалось сериализовать ключи')


    def deserialize_public_key(file: str):
        """
        Функция десериализации публичного ключа.

        :return: публичный ключ шифрования.
        """
        try:
            with open(file, "rb") as f:
                public_bytes = f.read()
                d_public_key = load_pem_public_key(public_bytes)
                logging.info('Ключ десериализован.')
        except OSError as err:
            logging.warning(f'{err} Не удалось десериализовать публичный ключ')
        return d_public_key

    def deserialize_private_key(file: str):
        """
        Функция десериализации приватного ключа.

        :return: приватный ключ шифрования
        """
        try:
            with open(file, "rb") as f:
                private_bytes = f.read()
                d_private_key = load_pem_private_key(private_bytes, password=None)
                logging.info('Ключ десериализован')
        except OSError as err:
            logging.warning(f'{err} Не удалось десериализовать ключ')
        return d_private_key

