import secrets

from . vecu import Vecu

class Vecu02(Vecu):
    def __init__(self):
        super(Vecu02, self).__init__()
        self._dids[2] = b'ISEhIENsYXJpbmV0ICEhIQ=='

    def is_read_did_allowed(self, id):
        # TODO: return correct failure code 0x33 when ECU is not unlocked.
        # TODO: return correct failure code when not in correct session
        if id == 0x0002 and self.session == 0x60 and self.security_level == 3:
            return True
        return False

    def _request_seed(self, security_level):
        if self.session == 0x60 and security_level == 0x3: 
            return secrets.token_bytes(4)
        return None

    def _expected_key(self, security_level):
        if security_level == 4:
            return bytes([x^0xFF for x in self.seed_store])
        return None



