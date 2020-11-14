from . vecu import Vecu

class Vecu01(Vecu):
    def __init__(self):
        super(Vecu01, self).__init__()
        self._dids[1] = b'LS0tU2F4b3Bob25lIC0tLQ=='#, 2:b'ISEhIENsYXJpbmV0ICEhIQ=='}

    def is_read_did_allowed(self, id):
        if id == 0x0001 and self.session == 0x03:
            return True
        return False


