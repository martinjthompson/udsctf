from . vecu import Vecu

class Vecu00(Vecu):
    def __init__(self):
        super(Vecu00, self).__init__()
        self._dids[0] = b'KiogUGlhbm9Gb3J0ZSAqKg=='

    def is_read_did_allowed(self, id):
        if id == 0x0000:
            return True
        return False


