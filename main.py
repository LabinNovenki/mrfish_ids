# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file '郭挺try.ui'
#
# Created by: PyQt5 UI code generator 5.15.4
#
# WARNING: Any manual changes made to this file will be lost when pyuic5 is
# run again.  Do not edit this file unless you know what you are doing.

import sys
from PyQt5.QtCore import *
import os
from PyQt5.QtGui import *
from PyQt5.QtWidgets import *
from PyQt5 import QtCore, QtGui, QtWidgets
from PyQt5 import QtCore, QtGui, QtWidgets
import time
import pandas as pd
import input_dealing as ipd
import receive

import threading as td
from identify import *
import test


class Sniff(QtCore.QThread):
    finishSignal = QtCore.pyqtSignal(list)

    def __init__(self, parent=None):
        super(Sniff, self).__init__(parent)
        pass

    def run(self):
        receive.start_sniff()


class Ui_MainWindow(QDialog):
    def setupUi(self, MainWindow):
        MainWindow.setObjectName("MainWindow")
        MainWindow.resize(1250, 800)
        self.centralwidget = QtWidgets.QWidget(MainWindow)
        self.centralwidget.setObjectName("centralwidget")

        # 按钮组合框
        self.groupBox = QtWidgets.QGroupBox(self.centralwidget)
        self.groupBox.setGeometry(QtCore.QRect(1050, 80, 130, 500))
        self.groupBox.setTitle("Menu")
        self.groupBox.setObjectName("groupBox")

        self.verticalLayoutWidget = QtWidgets.QWidget(self.groupBox)
        self.verticalLayoutWidget.setGeometry(QtCore.QRect(20, 10, 95, 500))
        self.verticalLayoutWidget.setObjectName("verticalLayoutWidget")

        self.verticalLayout = QtWidgets.QVBoxLayout(self.verticalLayoutWidget)
        self.verticalLayout.setContentsMargins(0, 0, 0, 0)
        self.verticalLayout.setObjectName("verticalLayout")

        self.pushButton = QtWidgets.QPushButton(self.verticalLayoutWidget)
        self.pushButton.setObjectName("pushButton")
        self.verticalLayout.addWidget(self.pushButton)
        self.pushButton_2 = QtWidgets.QPushButton(self.verticalLayoutWidget)
        self.pushButton_2.setObjectName("pushButton_con_log")
        self.verticalLayout.addWidget(self.pushButton_2)
        self.pushButton_con_log = QtWidgets.QPushButton(self.verticalLayoutWidget)
        self.pushButton_con_log.setObjectName("pushButton_con_log")
        self.verticalLayout.addWidget(self.pushButton_con_log)
        self.pushButton_3 = QtWidgets.QPushButton(self.verticalLayoutWidget)
        self.pushButton_3.setObjectName("pushButton_3")
        self.pushButton_4 = QtWidgets.QPushButton(self.verticalLayoutWidget)
        self.pushButton_4.setObjectName("pushButton_4")

        self.verticalLayout.addWidget(self.pushButton_3)
        self.verticalLayout.addWidget(self.pushButton_4)
        self.closeWinBtn = QtWidgets.QPushButton(self.verticalLayoutWidget)
        self.closeWinBtn.setObjectName("closeWinBtn")

        self.verticalLayout.addWidget(self.closeWinBtn)
        self.label = QtWidgets.QLabel(self.centralwidget)
        self.label.setGeometry(QtCore.QRect(90, 30, 301, 31))
        self.label.setObjectName("label")

        # submit按钮
        self.input_btn = QtWidgets.QPushButton(self.centralwidget)
        self.input_btn.setGeometry(QtCore.QRect(1070, 650, 100, 25))
        self.input_btn.show()
        self.input_btn.setObjectName("inputButton")

        # 输入框
        self.line_input = QLineEdit(self.centralwidget)  # 单行编辑框
        self.line_input.setGeometry(QtCore.QRect(40, 650, 985, 30))
        action = QAction(self)
        self.line_input.addAction(action, QLineEdit.TrailingPosition)
        self.line_input.setObjectName("line_input")
        self.line_input.show()

        # 文本显示框
        self.textEdit = QtWidgets.QTextEdit(self.centralwidget)
        self.textEdit.setGeometry(QtCore.QRect(40, 80, 985, 500))
        self.textEdit.setObjectName("textEdit")
        MainWindow.setCentralWidget(self.centralwidget)
        self.statusbar = QtWidgets.QStatusBar(MainWindow)
        self.statusbar.setObjectName("statusbar")
        MainWindow.setStatusBar(self.statusbar)

        self.retranslateUi(MainWindow)
        self.closeWinBtn.clicked.connect(MainWindow.close)
        self.pushButton_2.pressed.connect(self.pause)
        self.pushButton_3.pressed.connect(self.print_log_pkt)
        self.pushButton_con_log.pressed.connect(self.print_log_con)
        self.pushButton_4.pressed.connect(self.gethelp)
        self.pushButton.pressed.connect(self.myexec)
        self.input_btn.pressed.connect(self.input)

        # self.pushButton.pressed.connect(MainWindow.exec)
        QtCore.QMetaObject.connectSlotsByName(MainWindow)

        # 子线程
        self.sniff_td = Sniff()

    def retranslateUi(self, MainWindow):
        _translate = QtCore.QCoreApplication.translate
        MainWindow.setWindowTitle(_translate("MainWindow", "fishwall"))
        self.pushButton.setText(_translate("MainWindow", "start"))
        self.pushButton_2.setText(_translate("MainWindow", "pause"))
        self.pushButton_3.setText(_translate("MainWindow", "pkt log"))
        self.pushButton_con_log.setText(_translate("MainWindow", "con log"))
        self.pushButton_4.setText(_translate("MainWindow", "help"))
        self.closeWinBtn.setText(_translate("MainWindow", "quit"))
        self.input_btn.setText(_translate("MainWindow", "submit"))
        self.label.setText(_translate("MainWindow", "       欢迎使用mrfish智能入侵检测器"))
        welcome_str = 'welcome to the mrfish ver-0.5.5!\nmrfish is an intelligent ' \
                      'intrusion detector based on convolut' \
                      'ional neural network, click help to get detailed information of the software.'

        self.textEdit.setText(welcome_str)

    def getfile(self):
        fname, _ = QFileDialog.getOpenFileName(self, 'Open file', 'c:\\', "Image files (*.jpg *.gof)")
        self.le.setPixmap(QPixmap(fname))

    def print_log_pkt(self):
        data = ipd.print_log_pkt()
        self.textEdit.setText(data)
        self.textEdit.viewport().update()

    def print_log_con(self):
        data = ipd.print_log_con()
        self.textEdit.setText(data)
        self.textEdit.viewport().update()

    def gethelp(self):
        try:
            f = open('config/help', 'r')
        except:
            data = 'Can\'t find the file \'help\'.\nThe Local log file might be ' \
                   'modified or deleted.\nPlease check file integrity.'
            self.textEdit.setText(data)
            self.textEdit.viewport().update()
            return
        data = f.read()
        f.close()
        self.textEdit.setText(data)
        self.textEdit.viewport().update()

    def myexec(self):
        # td_sniff = td.Thread(target=receive.start_sniff(), name='sniff')
        # td_sniff.start()
        # receive.start_sniff()
        receive.PAUSE = False
        self.pushButton.setDisabled(True)
        self.sniff_td.start()

    def pause(self):
        receive.PAUSE = True
        self.sniff_td.quit()
        self.pushButton.setDisabled(False)

    def input(self):
        text = self.line_input.text()
        self.line_input.setSelection(0, len(text))
        output = ipd.input_dealing(text)
        self.textEdit.setText(output)
        self.textEdit.viewport().update()


import sys
from PyQt5.QtWidgets import QApplication, QWidget, QMainWindow
from PyQt5 import QtGui


if __name__ == '__main__':
    app = QApplication(sys.argv)
    form = QMainWindow()
    window = Ui_MainWindow()
    window.setupUi(form)

    form.show()
    sys.exit(app.exec_())
