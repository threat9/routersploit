class RoutersploitException(Exception):
    pass


class OptionValidationError(RoutersploitException):
    pass


class StopThreadPoolExecutor(RoutersploitException):
    pass
