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


class ThreadPoolExecutor(object):
    def __init__(self, threads):
        self.threads = threads
        self.data_producer = None

    def feed(self, dataset):
        self.data_producer = DataProducerThread(dataset)
        self.data_producer.start()
        time.sleep(0.1)

    def run(self, target):
        workers = []
        for worker_id in xrange(int(self.threads)):
            worker = WorkerThread(
                target=target,
                name='worker-{}'.format(worker_id),
            )
            workers.append(worker)
            worker.start()

        start = time.time()
        try:
            while worker.isAlive():
                worker.join(1)
        except KeyboardInterrupt:
            utils.print_info()
            utils.print_status("Waiting for already scheduled jobs to finish...")
            self.data_producer.stop()
            for worker in workers:
                worker.join()
        else:
            self.data_producer.join_queue()

        utils.print_status('Elapsed time: ', time.time() - start, 'seconds')
