import secrets
from binascii import hexlify
from . vecu import Vecu

class Vecu05(Vecu):
    def __init__(self):
        super(Vecu05, self).__init__()
        self._dids[5] = b'Li1WaW9sb25jZWxsbyAtLg=='
        self._known_seed = b'Ky'
        self._count = 0 # so we can return the current seed reasonably quickly

    def is_read_did_allowed(self, id):
        if id == 0x0005 and self.session == 0x60 and self.security_level == 3:
            return True
        return False

    def _request_seed(self, security_level):
        if self.session == 0x60 and security_level == 0x3: 
            if self._count % 1000 == 0:
                seed = self._known_seed
            else:
                seed = secrets.token_bytes(2)
            self._count += 1
            return seed
        return None

    def _expected_key(self, security_level):
        if security_level == 4 and self.seed_store == b'Ky':
            return b'OK'
        return None



