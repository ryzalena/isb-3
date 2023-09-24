import os
from cryptography.hazmat.primitives import (padding as sym_padding)
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import logging
import warnings
from cryptography.utils import CryptographyDeprecationWarning
from class_encoder import Flag

warnings.filterwarnings("ignore", category=CryptographyDeprecationWarning)


class Symmetric():
    def creating_keys(self) -> Flag:
        """

        Функция создания ключа

        :return: ключ или ошибку.
        """
        c_key = os.urandom(os.urandom(8))
    try:
        with open(self.file_settings['symmetric_key'], 'wb') as key_file:  # сериализация ключа симметричного алгоритма в файл
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


    def encryption(self) -> Flag:
        """

        Функция шифроки ключа методом CAST.

        :return: ключ или ошибку.
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

        padder = sym_padding.ANSIX923(32).padder()  # паддинг данных для работы блочного шифра
        padded_text = padder.update(bytes(text, 'UTF-8')) + padder.finalize()

        cipher = Cipher(algorithms.CAST5(dec_sym_key), modes.CBC(iv))  # шифрование текста симметричным алгоритмом
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

        Функция расшифроки методом CAST5.

        :return: ключ или ошибку.
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

        cipher = Cipher(algorithms.CAST5(dec_sym_key), modes.CBC(iv))  # дешифрование и депаддинг текста

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


    def receiving_decryption(self) -> bytes or Flag:
        """

        Функция получения и дешифроки ключа симметричного шифрования.

        :return: ключ или ошибку.
        """
        if (os.path.isfile(self.file_settings['private_key']) == False):
            return self.flag.file_error_keys.value
        else:
            try:
                with open(self.file_settings['private_key'], 'rb') as file:  # десериализация закрытого ключа
                    private_bytes = file.read()
            except IOError:
                logging.error(f"Ошибка: В файле {self.file_settings['private_key']}")

        d_private_key = load_pem_private_key(private_bytes, password=None, )

        if (os.path.isfile(self.file_settings['symmetric_key']) == False):
            return self.flag.file_error_keys.value
        else:
            try:
                with open(self.file_settings['symmetric_key'], 'rb') as file:  # десериализация ключа
                    sym_key = file.read()  # симметричного алгоритма
            except IOError:
                logging.error(f"Ошибка: В файле {self.file_settings['symmetric_key']}")

        dec_sym_key = d_private_key.decrypt(  # дешифрование текста асимметричным алгоритмом
            sym_key,
            as_padding.OAEP(
                mgf=as_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(), label=None))

        return dec_sym_key
