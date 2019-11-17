#!/use/bin/python3

import sys
from ui_bingo import Ui_MainWindow
from PySide2.QtWidgets import * 
from PySide2.QtGui import *

class MainWindow(QMainWindow):
    def __init__(self, parent = None):
        super(MainWindow, self).__init__()
        self.ui = Ui_MainWindow()
        self.ui.setupUi(self)
        self.ui.progressBar.setProperty("value", 50)

        self.ui.scene = QGraphicsScene()
        pixmap = QPixmap("./back.png")
        #self.ui.item = QGraphicsPixmapItem(pixmap)
        #self.ui.scene.addItem(self.ui.item)
        #self.ui.graphicsView.setScene(self.ui.scene)

        painter = QPainter()
        painter.begin(pixmap)
        painter.setPen(QColor(255.255,0,150))
        painter.setFont(QFont('Times', 30))
        painter.drawText(100,200,"TestMessage")
        painter.end()

        self.ui.item = QGraphicsPixmapItem(pixmap)
        self.ui.scene.addItem(self.ui.item)
        self.ui.graphicsView.setScene(self.ui.scene)

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec_())

