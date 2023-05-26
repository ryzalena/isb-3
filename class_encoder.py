import os
from cryptography.hazmat.primitives import (
    serialization, hashes, padding as sym_padding)
from PyQt5.QtWidgets import QFileDialog
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.serialization import load_pem_private_key
import logging
from cryptography.hazmat.primitives.asymmetric import (
    rsa, padding as as_padding)
import random
from enum import Enum
import warnings
from cryptography.utils import CryptographyDeprecationWarning


warnings.filterwarnings("ignore", category=CryptographyDeprecationWarning)


class Flag(Enum):
    file_error_text = 1
    file_error_enc_text = 2
    file_error_keys = 3
    file_error_enc_vec = 4
    file_good = 0


class Encoder():
    def __init__(self) -> None:     # Запуск программы
        self.way_to_init_text = str(QFileDialog.getOpenFileName(caption='Выберите файл для шифровки', filter='*.txt'))
        self.way_to_init_text = self.way_to_init_text.split('\'')[1]
        self.way = str(QFileDialog.getExistingDirectory(caption='Выберите папку для сохранения'))
        self.flag = Flag
        self.file_settings = {
            'initial_file': self.way_to_init_text,
            'encrypted_file': os.path.join(self.way, 'encrypted_file.txt'),
            'decrypted_file': os.path.join(self.way, 'decrypted_file.txt'),
            'symmetric_key': os.path.join(self.way, 'symmetric_key.txt'),
            'public_key': os.path.join(self.way, 'public_key.txt'),
            'private_key': os.path.join(self.way, 'private_key.txt'),
            'encrypted_vector': os.path.join(self.way, 'encrypted_vector.txt')
        }

        self.keys = [i for i in range(5, 17, 1)]

    def creating_keys(self) -> Flag:    # Генерация ключей
        len_key = random.randint(0, len(self.keys) - 1)
        sym_key = os.urandom(self.keys[len_key])

        assym_keys = rsa.generate_private_key(  # генерация пары ключей для асимметричного алгоритма шифрования
            public_exponent=65537,
            key_size=2048
        )
        private_key = assym_keys
        public_key = assym_keys.public_key()

        c_key = public_key.encrypt(                         # шифрование текста при помощи RSA-OAEP (усиливающая
            sym_key,                                        # классический RSA cхема с использованием
            as_padding.OAEP(                                # двух криптостойких хеш-функций и паддинга)
                mgf=as_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(), label=None))
        try:
            with open(self.file_settings['public_key'], 'wb') as public_out:    # сериализация открытого
                public_out.write(                                               # ключа в файл
                    public_key.public_bytes(
                        encoding=serialization.Encoding.PEM,
                        format=serialization.PublicFormat.SubjectPublicKeyInfo))
        except IOError:
            logging.error(f"Ошибка: В файле {self.file_settings['public_key']}")

        try:
            with open(self.file_settings['private_key'], 'wb') as private_out:      # сериализация закрытого
                private_out.write(                                                  # ключа в файл
                    private_key.private_bytes(
                        encoding=serialization.Encoding.PEM,
                        format=serialization.PrivateFormat.TraditionalOpenSSL,
                        encryption_algorithm=serialization.NoEncryption()))
        except IOError:
            logging.error(f"Ошибка: В файле {self.file_settings['private_key']}")

        try:
            with open(self.file_settings['symmetric_key'], 'wb') as key_file:       # сериализация ключа
                key_file.write(c_key)                                               # симмеричного алгоритма в файл
        except IOError:
            logging.error(f"error in file {self.file_settings['symmetric_key']}")

        iv = os.urandom(8)
        try:
            with open(self.file_settings['encrypted_vector'], 'wb') as enc_vec:
                enc_vec.write(iv)
        except IOError:
            logging.error(f"Ошибка: в файле {self.file_settings['encrypted_vector']}")

        return self.flag.file_good.value

    def receiving_decryption(self) -> bytes or Flag:  # Получение и дешифровка ключа симметричного шифрования
        if (os.path.isfile(self.file_settings['private_key']) == False):
            return self.flag.file_error_keys.value
        else:
            try:
                with open(self.file_settings['private_key'], 'rb') as file:     # десериализация закрытого ключа
                    private_bytes = file.read()
            except IOError:
                logging.error(f"Ошибка: В файле {self.file_settings['private_key']}")

        d_private_key = load_pem_private_key(private_bytes, password=None, )

        if (os.path.isfile(self.file_settings['symmetric_key']) == False):
            return self.flag.file_error_keys.value
        else:
            try:
                with open(self.file_settings['symmetric_key'], 'rb') as file:       # десериализация ключа
                    sym_key = file.read()                                           # симметричного алгоритма
            except IOError:
                logging.error(f"Ошибка: В файле {self.file_settings['symmetric_key']}")

        dec_sym_key = d_private_key.decrypt(           # дешифрование текста асимметричным алгоритмом
            sym_key,
            as_padding.OAEP(
                mgf=as_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(), label=None))

        return dec_sym_key

    def encryption(self) -> Flag:   # Шифровка методом CAST5
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

        padder = sym_padding.ANSIX923(32).padder()                  # паддинг данных для работы блочного шифра
        padded_text = padder.update(bytes(text, 'UTF-8')) + padder.finalize()

        cipher = Cipher(algorithms.CAST5(dec_sym_key), modes.CBC(iv))   # шифрование текста симметричным алгоритмом
        encryptor = cipher.encryptor()
        enc_text = encryptor.update(padded_text) + encryptor.finalize()

        try:
            with open(self.file_settings['encrypted_file'], 'wb') as file:
                file.write(enc_text)
        except IOError:
            logging.error(f"Ошибка: В файле {self.file_settings['encrypted_file']}")

        return self.flag.file_good.value

    def decryption(self) -> Flag:   # Расшифровка методом CAST5
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

        cipher = Cipher(algorithms.CAST5(dec_sym_key), modes.CBC(iv))   # дешифрование и депаддинг текста

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