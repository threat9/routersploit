from __future__ import print_function
from __future__ import absolute_import

import threading
from weakref import WeakKeyDictionary

try:
    import queue
except ImportError:
    import Queue as queue


data_queue = queue.Queue()
printer_queue = queue.Queue()


class DataProducerThread(threading.Thread):
    def __init__(self, data):
        super(DataProducerThread, self).__init__(name=self.__class__.__name__)
        self.data = data

    def run(self):
        for record in self.data:
            data_queue.put(record)


class WorkerThread(threading.Thread):
    def __init__(self):
        super(WorkerThread, self).__init__()

    def run(self):
        while not data_queue.empty():
            record = data_queue.get()
            self.target(record)
            data_queue.task_done()

    def target(self, record):
        pass


class PrinterThread(threading.Thread):
    def __init__(self):
        super(PrinterThread, self).__init__()
        self.daemon = True
        self.std_out = WeakKeyDictionary()

    def run(self):
        while True:
            content, sep, end, file_ = printer_queue.get()
            print(*content, sep=sep, end=end, file=file_)
            printer_queue.task_done()
