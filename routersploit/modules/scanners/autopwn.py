import time

from routersploit import (
    exploits,
    print_error,
    print_success,
    print_status,
    print_info,
    utils,
    threads,
)


class Exploit(exploits.Exploit):
    """
    Scanner implementation for all vulnerabilities.
    """
    __info__ = {
        'name': 'AutoPwn',
        'description': 'Scanner module for all vulnerabilities.',
        'authors': [
            'Marcin Bury <marcin.bury[at]reverse-shell.com>',  # routersploit module
        ],
        'references': (
            '',
        ),
        'devices': (
            'Multi',
        ),
    }

    target = exploits.Option('', 'Target IP address e.g. 192.168.1.1')  # target address
    port = exploits.Option(80, 'Target port')  # default port
    threads = exploits.Option(8, "Number of threads")

    def run(self):
        self.vulnerabilities = []
        data_producer = threads.DataProducerThread(utils.iter_modules(utils.EXPLOITS_DIR))
        data_producer.start()
        time.sleep(1)

        workers = []
        for worker_id in xrange(int(self.threads)):
            worker = threads.WorkerThread(
                target=self.target_function,
                name='worker-{}'.format(worker_id),
            )
            workers.append(worker)
            worker.start()

        try:
            while worker.isAlive():
                worker.join(1)
        except KeyboardInterrupt:
            print_info()
            print_status("Waiting for already scheduled jobs to finish...")
            data_producer.stop()
            for worker in workers:
                worker.join()
        else:
            data_producer.join_queue()

        if self.vulnerabilities:
            print_info()
            print_success("Device is vulnerable!")
            for v in self.vulnerabilities:
                print_info(" - {}".format(v))
        else:
            print_error("Device is not vulnerable to any exploits!\n")

    def check(self):
        raise NotImplementedError("Check method is not available")

    def target_function(self, exploit):
        exploit = exploit()
        exploit.target = self.target
        exploit.port = self.port

        response = exploit.check()

        if response is True:
            print_success("{} is vulnerable".format(exploit))
            self.vulnerabilities.append(exploit)
        elif response is False:
            print_error("{} is not vulnerable".format(exploit))
        else:
            print_status("{} could not be verified".format(exploit))
