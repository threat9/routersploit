import logging


LOGGER = logging.getLogger(__name__)


class RoutersploitException(Exception):
    def __init__(self, msg=''):
        super(RoutersploitException, self).__init__(msg)
        LOGGER.exception(self)


class OptionValidationError(RoutersploitException):
    pass


class StopThreadPoolExecutor(RoutersploitException):
    pass
