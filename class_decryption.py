import os
from cryptography.hazmat.primitives import padding as sym_padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import logging
from class_encoder import Flag

class Decryption():

    def decryption(self) -> Flag:
        """

        Расшифровка методом CAST5.

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