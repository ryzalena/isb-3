import os
from PyQt5.QtWidgets import QFileDialog
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
    def __init__(self) -> None:  # Запуск программы

        self.flag = Flag
        self.file_settings = {
            path_to_text = "isb-3\initial_file.txt",
            way_to_files = "isb-3\files",
            'initial_file': self.way_to_init_text,
            'encrypted_file': os.path.join(self.way, 'encrypted_file.txt'),
            'decrypted_file': os.path.join(self.way, 'decrypted_file.txt'),
            'symmetric_key': os.path.join(self.way, 'symmetric_key.txt'),
            'public_key': os.path.join(self.way, 'public_key.txt'),
            'private_key': os.path.join(self.way, 'private_key.txt'),
            'encrypted_vector': os.path.join(self.way, 'encrypted_vector.txt')
        }
        self.way_to_init_text = path_to_text
        self.way_to_init_text = self.way_to_init_text.split('\'')[1]
        self.way = way_to_files
        self.keys = [i for i in range(5, 17, 1)]