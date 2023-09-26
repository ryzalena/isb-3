import os
from cryptography.hazmat.primitives import (
    hashes, padding as sym_padding)
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.serialization import load_pem_private_key
import logging
from cryptography.hazmat.primitives.asymmetric import (
     padding as as_padding)
import random
from enum import Enum
import warnings
from cryptography.utils import CryptographyDeprecationWarning
from class_asym import keys

warnings.filterwarnings("ignore", category=CryptographyDeprecationWarning)


class Flag(Enum):
    file_error_text = 1
    file_error_enc_text = 2
    file_error_keys = 3
    file_error_enc_vec = 4
    file_good = 0


class Encoder():
    def __init__(self) -> None:
        self.flag = Flag
        self.file_settings = {
            'initial_file': "files/initial_file.txt",
            'encrypted_file': "files/encrypted_file.txt",
            'decrypted_file': "files/decrypted_file.txt",
            'symmetric_key': "files/symmetric_key.txt",
            'public_key': "files/public_key.txt",
            'private_key': "files/private_key.txt",
            'encrypted_vector': "files/encrypted_vector.txt"
        }

        self.keys = [i for i in range(5, 17, 1)]

    def creating_keys(self) -> Flag:
        """

        Функция для генерации ключей.

        :return: Flag, состояние программы.
        """
        len_key = random.randint(0, len(self.keys) - 1)
        sym_key = os.urandom(self.keys[len_key])

        c_key = keys(sym_key)

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

    def receiving_decryption(self) -> bytes or Flag:
        """

        Функция получения и дешифроки ключа симметричного шифрования.

        :return: ключ или ошибку.
        """
        if (os.path.isfile(self.file_settings['private_key']) == False):
            return self.flag.file_error_keys.value
        else:
            try:
                with open(self.file_settings['private_key'], 'rb') as file:
                    private_bytes = file.read()
            except IOError:
                logging.error(f"Ошибка: В файле {self.file_settings['private_key']}")

        d_private_key = load_pem_private_key(private_bytes, password=None, )

        if (os.path.isfile(self.file_settings['symmetric_key']) == False):
            return self.flag.file_error_keys.value
        else:
            try:
                with open(self.file_settings['symmetric_key'], 'rb') as file:
                    sym_key = file.read()
            except IOError:
                logging.error(f"Ошибка: В файле {self.file_settings['symmetric_key']}")

        dec_sym_key = d_private_key.decrypt(
            sym_key,
            as_padding.OAEP(
                mgf=as_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(), label=None))

        return dec_sym_key

    def encryption(self) -> Flag:
        """

        Функция для шифрования методом CAST.

        :return: Flag, состояние программы.
        """
        if (os.path.isfile(self.file_settings['initial_file']) == False):
            return self.flag.file_error_text.value
        else:
            try:
                with open(self.file_settings['initial_file'], 'r', encoding='UTF-8') as file:
                    text = file.read()
            except IOError:
                logging.error(f"Ошибка: В файле {self.file_settings['initial_file']}")

        if (os.path.isfile(self.file_settings['encrypted_vector']) == False):
            return self.flag.file_error_enc_vec.value
        else:
            try:
                with open(self.file_settings['encrypted_vector'], 'rb') as file:
                    iv = file.read()
            except IOError:
                logging.error(f"Ошибка: В файле {self.file_settings['encrypted_vector']}")

        if (self.receiving_decryption() == 3):
            return self.flag.file_error_keys.value
        else:
            dec_sym_key = self.receiving_decryption()

        padder = sym_padding.ANSIX923(32).padder()
        padded_text = padder.update(bytes(text, 'UTF-8')) + padder.finalize()

        cipher = Cipher(algorithms.CAST5(dec_sym_key), modes.CBC(iv))
        encryptor = cipher.encryptor()
        enc_text = encryptor.update(padded_text) + encryptor.finalize()

        try:
            with open(self.file_settings['encrypted_file'], 'wb') as file:
                file.write(enc_text)
        except IOError:
            logging.error(f"Ошибка: В файле {self.file_settings['encrypted_file']}")

        return self.flag.file_good.value

    def decryption(self) -> Flag:
        """

        Функция для расшифровки методом CAST5.

        :return: Flag, состояние программы.
        """
        if (os.path.isfile(self.file_settings['encrypted_file']) == False):
            return self.flag.file_error_enc_text.value
        else:
            try:
                with open(self.file_settings['encrypted_file'], 'rb') as file:
                    enc_text = file.read()
            except IOError:
                logging.error(f"Ошибка: В файле {self.file_settings['encrypted_file']}")

        if (os.path.isfile(self.file_settings['encrypted_vector']) == False):
            return self.flag.file_error_enc_vec.value
        else:
            try:
                with open(self.file_settings['encrypted_vector'], 'rb') as file:
                    iv = file.read()
            except IOError:
                logging.error(f"Ошибка: В файле {self.file_settings['encrypted_vector']}")

        if (self.receiving_decryption() == 3):
            return self.flag.file_error_keys.value
        else:
            dec_sym_key = self.receiving_decryption()

        cipher = Cipher(algorithms.CAST5(dec_sym_key), modes.CBC(iv))

        decryptor = cipher.decryptor()
        dc_text = decryptor.update(enc_text) + decryptor.finalize()

        unpadder = sym_padding.ANSIX923(32).unpadder()
        unpadded_dc_text = unpadder.update(dc_text) + unpadder.finalize()
        unpadded_dc_text = unpadded_dc_text.decode('UTF-8')

        try:
            with open(self.file_settings['decrypted_file'], 'w') as file:
                file.write(unpadded_dc_text)
        except IOError:
            logging.error(f"error in file {self.file_settings['decrypted_file']}")

        return self.flag.file_good.value