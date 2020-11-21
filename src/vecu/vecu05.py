import secrets

from . vecu import Vecu

class Vecu05(Vecu):
    def __init__(self):
        super(Vecu05, self).__init__()
        self._dids[5] = b'Li1WaW9sb25jZWxsbyAtLg=='

    def is_read_did_allowed(self, id):
        if id == 0x0005 and self.session == 0x60 and self.security_level == 3:
            return True
        return False

    def _request_seed(self, security_level):
        if self.session == 0x60 and security_level == 0x3: 
            return secrets.token_bytes(2)
        return None

    def _expected_key(self, security_level):
        if security_level == 4 and self.seed_store == b'Ky':
            return b'OK'
        return None



