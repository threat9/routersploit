from __future__ import print_function
from __future__ import absolute_import

import threading
from weakref import WeakKeyDictionary

try:
    import queue
except ImportError:
    import Queue as queue


printer_queue = queue.Queue()
thread_output_stream = WeakKeyDictionary()


class PrinterThread(threading.Thread):
    def __init__(self):
        super(PrinterThread, self).__init__()
        self.daemon = True

    def run(self):
        while True:
            content, sep, end, file_, thread = printer_queue.get()
            print(*content, sep=sep, end=end, file=file_)
            printer_queue.task_done()
