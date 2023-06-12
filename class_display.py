from PyQt5 import QtCore
from PyQt5.QtGui import QFont
from class_encoder import Encoder as enc
from PyQt5.QtWidgets import (QPushButton, QMainWindow, QLabel)

from class_encryption import Encryption
from class_keys import Keys
from class_decryption import Decryption

class Display(QMainWindow):
    def __init__(self) -> None:
        flag = 0
        super().__init__()
        self.basic_settings()

    def basic_settings(self) -> None:
        """

        Основные характеристики окна с выводом

        """
        self.enc = enc()
        self.info_message = QLabel(self)
        self.btn_creating_keys = QPushButton('Сгенерировать ключи', self)
        self.btn_enc_txt = QPushButton('Зашифровать текст', self)
        self.btn_dec_txt = QPushButton('Дешифровать текст', self)

        self.details_settings()

        self.setFixedWidth(self.w)
        self.setFixedHeight(self.h)
        self.move(0, 0)
        self.setWindowTitle('Квазимодо')
        self.setStyleSheet('background-color: #faeedd;')
        self.show()

    def details_settings(self) -> None:
        """

        Характеристики элементов.

        """
        self.w = 1050
        self.h = 200
        self.info_message.resize(self.w, self.h)
        self.info_message.setFont(QFont('Calibri', 14))
        self.info_message.setAlignment(QtCore.Qt.AlignRight)

        self.btn_x_size = 350
        self.btn_y_size = 50
        self.luft = 0
        self.btn_font_main = QFont('Calibri', 14)
        self.btn_StyleSheet_main = 'background-color: #fff1a8; color: #4e1609; border :2px solid #4e1609;'

        self.btn_creating_keys.setGeometry(0, 0, self.btn_x_size, self.btn_y_size)
        self.btn_creating_keys.setFont(self.btn_font_main)
        self.btn_creating_keys.setStyleSheet(self.btn_StyleSheet_main)
        self.btn_creating_keys.clicked.connect(self.creating_keys)

        self.btn_enc_txt.setGeometry(0, 55, self.btn_x_size, self.btn_y_size)
        self.btn_enc_txt.setFont(self.btn_font_main)
        self.btn_enc_txt.setStyleSheet(self.btn_StyleSheet_main)
        self.btn_enc_txt.clicked.connect(self.encryption)

        self.btn_dec_txt.setGeometry(0, 110,
                                     self.btn_x_size, self.btn_y_size)
        self.btn_dec_txt.setFont(self.btn_font_main)
        self.btn_dec_txt.setStyleSheet(self.btn_StyleSheet_main)
        self.btn_dec_txt.clicked.connect(self.decryption)


    def output(self, text: str) -> None:
        """ 
        
        Вывод сообщений.

        """
        self.info_message.clear()
        self.info_message.setText(text)
        self.info_message.show()

    def creating_keys(self) -> None:
        """

        Вывод текста на кнопке для создания ключей.

        """
        flag = self.Keys.creating_keys()
        if (flag == 0):
            self.output(
                'Ключ шифрования создан, соответсующий файл создан.')
        elif (flag == 1):
            self.output(
                'Ошибка: Невозможно открыть файл.')

    def encryption(self) -> None:
        """

        Вывод текста с кнопки для шифровки.

        """
        flag = self.Encryption.encryption()
        if (flag == 0):
            self.output(
                'Текст зашифрован, соответсвующий файл создан.')
        elif (flag == 1):
            self.output(
                'Ошибка: Невозможно открыть файл с текстом')
        elif (flag == 3):
            self.output('Ошибка: Невозможно открыть файл с ключами')
        elif (flag == 4):
            self.output(
                'Ошибка: Невозможно открыть файлу с вектором шифрования')

    def decryption(self) -> None:
        """

        Вывод текста на кнопке для расшифроки.

        """
        flag = self.Decryption.decryption()
        if (flag == 0):
            self.output(
                'Текст расшифрован и записан в файл.')
        elif (flag == 2):
            self.output(
                'Ошибка: Невозможно открыть файл с зашифрованным текстом')
        elif (flag == 3):
            self.output('Ошибка: Невозможно открыть файл с ключами')
        elif (flag == 4):
            self.output(
                'Ошибка: Невозможно открыть файл с вектором шифрования')