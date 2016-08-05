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


class WorkerThread(threading.Thread):
    def __init__(self, name):
        super(WorkerThread, self).__init__(name=name)
        self.name = name

    def run(self):
        while not data_queue.empty():
            record = data_queue.get()
            target = record[0]
            args = record[1:]
            try:
                target(*args)
            finally:
                data_queue.task_done()


class ThreadPoolExecutor(object):
    def __init__(self, threads):
        self.threads = threads
        self.workers = []

    def __enter__(self):
        self.workers = []
        for worker_id in xrange(int(self.threads)):
            worker = WorkerThread(
                name='worker-{}'.format(worker_id),
            )
            self.workers.append(worker)
        return self

    def __exit__(self, *args):
        for worker in self.workers:
            worker.start()

        start = time.time()
        try:
            while worker.isAlive():
                worker.join(1)
        except KeyboardInterrupt:
            utils.print_info()
            utils.print_status("Waiting for already scheduled jobs to finish...")
            data_queue.queue.clear()
            for worker in self.workers:
                worker.join()
        else:
            data_queue.join()

        utils.print_status('Elapsed time: ', time.time() - start, 'seconds')

    def submit(self, *args):
        data_queue.put(args)
