from time import sleep
import secrets

from . vecu import Vecu

class Vecu10(Vecu):
    def __init__(self):
        super(Vecu10, self).__init__()
        self._dids[10] = b'KCgtIFRyb21ib25lIC0pKQ=='
        self._uds_seed = secrets.token_bytes(4)
        self._uds_key = secrets.token_bytes(4)
    def is_read_did_allowed(self, id):
        if id == 10 and self.session == 0x60 and self.security_level == 3:
            return True
        return False

    def _request_seed(self, security_level):
        if self.session == 0x60 and security_level == 0x3: 
            return self._uds_seed
        return None

    def _expected_key(self, security_level):
        if security_level == 4: 
            return self._uds_key
        return None


    def _compare(self, got, expected):
        if len(got) != len(expected):
            return False
        for i in range(len(got)):
            if got[i] != expected[i]:
                return False
            sleep(0.1)
            return True



