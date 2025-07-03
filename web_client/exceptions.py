class NotAuthenticatedException(Exception):
    def __init__(self):
        super().__init__("No valid session token. Please authenticate first.")


class OtherException(Exception):
    def __init__(self):
        super().__init__("Other Exception.")


class OperationFailedException(Exception):
    def __init__(self, code, message):
        super().__init__(message)
        self.code = code
