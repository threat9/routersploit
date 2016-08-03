from __future__ import print_function

import threading
from weakref import WeakKeyDictionary

try:
    import queue
except ImportError:
    import Queue as queue


data_queue = queue.Queue()
printer_queue = queue.Queue()

thread_output_stream = WeakKeyDictionary()


class DataProducerThread(threading.Thread):
    def __init__(self, data):
        super(DataProducerThread, self).__init__(name=self.__class__.__name__)
        self.data = data

    def run(self):
        for record in self.data:
            data_queue.put(record)

    def stop(self):
        data_queue.queue.clear()

    def join_queue(self):
        data_queue.join()


class WorkerThread(threading.Thread):
    def __init__(self, target, name):
        super(WorkerThread, self).__init__(target=target, name=name)
        self.target = target
        self.name = name

    def run(self):
        while not data_queue.empty():
            record = data_queue.get()
            try:
                self.target(record)
            finally:
                data_queue.task_done()


class PrinterThread(threading.Thread):
    def __init__(self):
        super(PrinterThread, self).__init__()
        self.daemon = True

    def run(self):
        while True:
            content, sep, end, file_, thread = printer_queue.get()
            print(*content, sep=sep, end=end, file=file_)
            printer_queue.task_done()
