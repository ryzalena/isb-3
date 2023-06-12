import os
from cryptography.hazmat.primitives import padding as sym_padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import logging
from class_encoder import Flag



class Encryption():

    def encryption(self) -> Flag:
        """

        Шифровка методом CAST5.

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


