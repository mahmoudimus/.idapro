#!/usr/bin/env python
import sys
import time

from PySide6 import QtCore, QtWidgets

QApplication = QtWidgets.QApplication
QWidget = QtWidgets.QWidget

TOTAL_WIDGETS = 10


class Worker(QtCore.QObject):
    processed = QtCore.Signal(int)
    finished = QtCore.Signal()

    # Overriding this is not necessary if you're not doing anything in it.

    # def __init__(self):
    #     super(Worker, self).__init__()

    def helloWorld(self):
        for i in range(TOTAL_WIDGETS):
            # We sleep first to simulate an operation taking place.
            time.sleep(0.5)
            print("hello %s" % i)
            self.processed.emit(i + 1)
        # Must manually emit the finished signal.
        self.finished.emit()


class MainUI(QWidget):
    def __init__(self, parent=None):
        super(MainUI, self).__init__(parent)
        self.extraThread = QtCore.QThread()

        # IMPORTANT: Don't quit the app until the thread has
        # completed. Prevents errors like:
        #
        #     QThread: Destroyed while thread is still running
        #
        QApplication.instance().aboutToQuit.connect(self.quit)

        self.worker = Worker()
        self.worker.moveToThread(self.extraThread)
        self.setupUI()
        self.connectSignalsAndSlots()

    def setupUI(self):
        # CREAT MAIN LAYOUT AND WIDGETS
        mainLayout = QtWidgets.QVBoxLayout()
        btnLayout = QtWidgets.QHBoxLayout()
        mainLayout.addLayout(btnLayout)
        self.setLayout(mainLayout)

        self.progressBar = QtWidgets.QProgressBar(self)
        self.progressBar.setRange(0, TOTAL_WIDGETS)
        self.progressBar.setVisible(False)
        self.btnWork = QtWidgets.QPushButton("Do Work")
        self.btnCancel = QtWidgets.QPushButton("Cancel")
        self.btnCancel.setDisabled(True)

        self.guiResponseProgressbar = QtWidgets.QProgressBar(self)
        self.guiResponseProgressbar.setRange(0, 0)

        self.outputWindow = QtWidgets.QTextEdit()

        mainLayout.addWidget(self.progressBar)
        mainLayout.addWidget(self.outputWindow)
        mainLayout.addWidget(self.guiResponseProgressbar)

        btnLayout.addWidget(self.btnWork)
        btnLayout.addWidget(self.btnCancel)

    def connectSignalsAndSlots(self):
        print("connecting signals")
        self.btnWork.clicked.connect(self.startWorker)

        # Pleas see <http://nooooooooooooooo.com/>. Bad bad bad bad bad.
        # self.btnCancel.clicked.connect(self.extraThread.terminate)

        # THREAD STARTED
        # Not necessary; just do this in startWorker.
        # self.extraThread.started.connect(lambda: self.btnWork.setDisabled(True))
        # self.extraThread.started.connect(lambda:self.btnCancel.setEnabled(True))
        # self.extraThread.started.connect(self.progressBar.show)
        self.extraThread.started.connect(self.worker.helloWorld)

        # THREAD FINISHED
        # self.extraThread.finished.connect(lambda:self.btnCancel.setDisabled(True))
        # self.extraThread.finished.connect(self.extraThread.deleteLater)
        # self.extraThread.finished.connect(self.worker.deleteLater)
        self.extraThread.finished.connect(self.finished)

        # Connect worker signals.
        self.worker.processed.connect(self.progressBar.setValue)
        self.worker.finished.connect(self.finished)

        # SHOW PROGRESS BAR WHEN PUBLISHING STARTS
        # self.extraThread.started.connect(self.progressBar.show)
        # CONNECT PROCESS TO PROGRESS BAR AND OUTPUT WINDOW
        # NOT DONE YET

    def startWorker(self):
        # GO
        self.btnWork.setDisabled(True)
        self.btnCancel.setEnabled(True)
        self.progressBar.show()
        print("starting worker thread")
        self.extraThread.start()

        # THIS IS BLOCKING THE GUI THREAD! Try putting this back in and seeing
        # what happens to the gui_response_progressbar.

        # for i in xrange(10):
        #     print 'from main thread:', i
        #     time.sleep(.3)

    def finished(self):
        print("finished")
        self.btnCancel.setDisabled(True)
        # self.extraThread.deleteLater()
        # self.worker.deleteLater()

    def quit(self):
        # Quit the thread's event loop. Note that this *doesn't* stop tasks
        # running in the thread, it just stops the thread from dispatching
        # events.
        self.extraThread.quit()
        # Wait for the thread to complete. If the thread's task is not done,
        # this will block.
        self.extraThread.wait()


if __name__ == "__main__":
    args = sys.argv
    app = QApplication(args)
    p = MainUI()
    p.show()
    # Annoyance on Mac OS X.
    p.raise_()
    sys.exit(app.exec_())
