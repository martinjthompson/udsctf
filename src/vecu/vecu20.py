from time import time
import secrets
from binascii import hexlify
from . vecu import Vecu
from udsoncan import Response, services

class Vecu20(Vecu):
    def __init__(self):
        super(Vecu20, self).__init__()
        self._target_did = 16
        self._dids[20] = b'LC47IFRpbS5wYW5pIDsuLA=='
        self._target_session = 0x60
        self._target_level = 3

    def is_read_did_allowed(self, did):
        if self.session == self._target_session and self.security_level == self._target_level:
            return True
        return False

    def _request_seed(self, security_level):
        self._uds_seed = secrets.randbits(128).to_bytes(128//8, "big")
        return self._uds_seed

    def _expected_key(self, security_level):
        key = bytearray()
        for b in self._uds_seed:
            key.append(b^0x35)
        self.log.debug(" Key: %s", hexlify(key))
        self._uds_key = bytes(key)
        return self._uds_key
