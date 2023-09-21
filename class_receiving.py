import os
from cryptography.hazmat.primitives import (hashes)
from cryptography.hazmat.primitives.serialization import load_pem_private_key
import logging
from cryptography.hazmat.primitives.asymmetric import (padding as as_padding)
import warnings
from cryptography.utils import CryptographyDeprecationWarning
from class_encoder import Flag

warnings.filterwarnings("ignore", category=CryptographyDeprecationWarning)

class Receiving():
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
