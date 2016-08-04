from __future__ import print_function
from __future__ import absolute_import

import threading
import time

try:
    import queue
except ImportError:
    import Queue as queue

from . import utils


data_queue = queue.Queue()


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
