from __future__ import print_function
from __future__ import absolute_import

import threading
import time

try:
    import queue
except ImportError:
    import Queue as queue

from . import utils
from .exceptions import StopThreadPoolExecutor


data_queue = queue.Queue()
data_producing = threading.Event()


class WorkerThread(threading.Thread):
    def __init__(self, name):
        super(WorkerThread, self).__init__(name=name)
        self.name = name

    def run(self):
        while data_producing.is_set() or not data_queue.empty():
            record = data_queue.get()
            target = record[0]
            args = record[1:]
            try:
                target(*args)
            except StopThreadPoolExecutor:
                utils.print_info()
                utils.print_status("Waiting for already scheduled jobs to finish...")
                data_queue.queue.clear()
            finally:
                data_queue.task_done()


class ThreadPoolExecutor(object):
    def __init__(self, threads):
        self.threads = threads
        self.workers = []
        self.worker = None
        self.start_time = None

    def __enter__(self):
        self.workers = []
        data_producing.set()
        for worker_id in xrange(int(self.threads)):
            worker = WorkerThread(
                name='worker-{}'.format(worker_id),
            )
            worker.start()
            self.workers.append(worker)

        self.worker = worker
        self.start_time = time.time()
        return self

    def __exit__(self, *args):
        data_producing.clear()
        try:
            while self.worker.isAlive():
                self.worker.join(1)
        except KeyboardInterrupt:
            utils.print_info()
            utils.print_status("Waiting for already scheduled jobs to finish...")
            data_queue.queue.clear()
        finally:
            for worker in self.workers:
                worker.join()
            data_queue.unfinished_tasks = 0

        utils.print_status('Elapsed time: ', time.time() - self.start_time, 'seconds')

    def submit(self, *args):
        data_queue.put(args)
