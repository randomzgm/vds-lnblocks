#!/usr/bin/python3
import sys
import wallet_rpc

from PyQt5.QtGui import QTextCursor
from PyQt5.QtCore import QObject, pyqtSignal
from PyQt5.QtWidgets import (QWidget, QLabel, QLineEdit, QTextEdit, QGridLayout, QApplication, QDesktopWidget,
                             QPushButton, QHBoxLayout, QButtonGroup, QRadioButton)


class Stream(QObject):
    """Redirects console output to text widget."""
    newText = pyqtSignal(str)

    def write(self, text):
        self.newText.emit(str(text))


class Windows(QWidget):

    def __init__(self):
        super().__init__()

        self.urlEdit = QLineEdit()
        self.bodyEdit = QTextEdit()
        self.nameEdit = QLineEdit()
        self.secretEdit = QLineEdit()
        self.methodGroup = QButtonGroup()
        self.getButton = QRadioButton("GET")
        self.postButton = QRadioButton("POST")
        self.postButton.setChecked(True)
        self.methodGroup.addButton(self.getButton)
        self.methodGroup.addButton(self.postButton)
        self.responseEdit = QTextEdit()

        self.initUi()

        # Custom output stream.
        wallet_rpc.logger.handlers[1].stream = Stream(newText=self.onUpdateText)
        sys.stderr = Stream(newText=self.onUpdateText)

    def __del__(self):
        # Restore sys.stdout
        sys.stdout = sys.__stdout__
        sys.stderr = sys.__stderr__

    def onUpdateText(self, text):
        """Write console output to text widget."""
        cursor = self.responseEdit.textCursor()
        cursor.movePosition(QTextCursor.End)
        cursor.insertText(text)
        self.responseEdit.setTextCursor(cursor)
        self.responseEdit.ensureCursorVisible()

    def initUi(self):
        urlLabel = QLabel('Url')
        bodyLabel = QLabel('Body')
        nameLabel = QLabel('UserName')
        secretLabel = QLabel('Secret')
        methodLable = QLabel('Method')
        responseLabel = QLabel('Response')

        callButton = QPushButton("CALL")
        callButton.clicked.connect(self.buttonClick)

        grid = QGridLayout()
        grid.setSpacing(10)

        grid.addWidget(urlLabel, 1, 0)
        grid.addWidget(self.urlEdit, 1, 1)

        grid.addWidget(bodyLabel, 2, 0)
        grid.addWidget(self.bodyEdit, 2, 1)

        grid.addWidget(nameLabel, 3, 0)
        grid.addWidget(self.nameEdit, 3, 1)

        grid.addWidget(secretLabel, 4, 0)
        grid.addWidget(self.secretEdit, 4, 1)

        grid.addWidget(methodLable, 5, 0)
        box = QHBoxLayout()
        box.addWidget(self.getButton)
        box.addWidget(self.postButton)
        grid.addLayout(box, 5, 1)

        hBox = QHBoxLayout()
        hBox.addStretch(1)
        hBox.addWidget(callButton)
        grid.addLayout(hBox, 6, 1)

        grid.addWidget(responseLabel, 7, 0)
        grid.addWidget(self.responseEdit, 7, 1)

        self.setLayout(grid)

        self.setGeometry(500, 600, 1000, 800)
        self.center()
        self.setWindowTitle('Call Kong Service')
        self.show()

    def center(self):
        # 获得窗口
        qr = self.frameGeometry()
        # 获得屏幕中心点
        cp = QDesktopWidget().availableGeometry().center()
        # 显示到屏幕中心
        qr.moveCenter(cp)
        self.move(qr.topLeft())

    def buttonClick(self):
        wallet_rpc.call(self.urlEdit.text(), self.nameEdit.text(), self.secretEdit.text(), self.bodyEdit.toPlainText(),
                        self.methodGroup.checkedButton().text())


if __name__ == '__main__':
    app = QApplication(sys.argv)
    ex = Windows()
    sys.exit(app.exec_())
