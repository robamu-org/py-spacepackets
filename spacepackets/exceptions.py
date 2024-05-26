class BytesTooShortError(ValueError):
    """When unpacking something from raw :py:class:`bytes`, the length of the bytearray was too
    short."""

    def __init__(self, expected_len: int, bytes_len: int):
        super().__init__(
            f"bytearray with length {bytes_len} shorter than expected {expected_len}"
        )
        self.expected_len = expected_len
        self.bytes_len = bytes_len


class InvalidCrcCcitt16(Exception):
    def __init__(self, data: bytes):
        self.data = data
