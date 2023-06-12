import os
from cryptography.hazmat.primitives import (serialization, hashes)
import logging
from cryptography.hazmat.primitives.asymmetric import (
    rsa, padding as as_padding)
import random
from class_encoder import Flag



class Keys():

    def __init__(self) -> None:
      self.keys = [i for i in range(5, 17, 1)]


    def creating_keys(self) -> Flag:
        """

        #Функция для генерации ключей.

        #:return: Flag, состояние программы.
        """
        len_key = random.randint(0, len(self.keys) - 1)
        sym_key = os.urandom(self.keys[len_key])

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
            with open(self.file_settings['public_key'], 'wb') as public_out:
                public_out.write(
                    public_key.public_bytes(
                        encoding=serialization.Encoding.PEM,
                        format=serialization.PublicFormat.SubjectPublicKeyInfo))
        except IOError:
            logging.error(f"Ошибка: В файле {self.file_settings['public_key']}")

        try:
            with open(self.file_settings['private_key'], 'wb') as private_out:
                private_out.write(
                    private_key.private_bytes(
                        encoding=serialization.Encoding.PEM,
                        format=serialization.PrivateFormat.TraditionalOpenSSL,
                        encryption_algorithm=serialization.NoEncryption()))
        except IOError:
            logging.error(f"Ошибка: В файле {self.file_settings['private_key']}")

        try:
            with open(self.file_settings['symmetric_key'], 'wb') as key_file:
                key_file.write(c_key)
        except IOError:
            logging.error(f"error in file {self.file_settings['symmetric_key']}")

        iv = os.urandom(8)
        try:
            with open(self.file_settings['encrypted_vector'], 'wb') as enc_vec:
                enc_vec.write(iv)
        except IOError:
            logging.error(f"Ошибка: в файле {self.file_settings['encrypted_vector']}")

        return self.flag.file_good.value