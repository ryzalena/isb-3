import logging
import sys
from class_display import Display
from PyQt5.QtWidgets import (QApplication)


if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO, filename='logs.log', filemode='w')
    app = QApplication(sys.argv)
    ex = Display()
    sys.exit(app.exec_())