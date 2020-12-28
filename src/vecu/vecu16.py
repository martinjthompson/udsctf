from time import time
import secrets

from . vecu import Vecu
from . vecu15 import Vecu15
from udsoncan import Response, services

class Vecu16(Vecu15):
    def __init__(self):
        self.init_saved()
        super(Vecu16, self).__init__()
        self._target_did = 16
        self._dids[16] = b'e1soIFJlY29yZGVyICldfQ=='
        self._target_session = 0x60
        self._target_level = 3

    def init_saved(self):
        self._saved = (0, 1, None)
        self.restore_saved()
        
    def restore_saved(self):
        self._saved_session, self._timeout, self._last_fail_time = self._saved

    def reset(self):
        self._saved = (self.session, self._timeout, self._last_fail_time)
        super(Vecu15, self).reset()
        self.restore_saved()
        self.log.debug("Reset: %s %s %s", self._saved_session, self._timeout, self._last_fail_time)
    
    def diagnostic_session_control(self, req):
        self.log.debug("Session change: %s %d", self._saved, req.subfunction)
        # reset timers good switch to new session
        response = super(Vecu15, self).diagnostic_session_control(req)
        if response.code == Response.Code.PositiveResponse and self._saved[0] != self.session:
            self.log.debug("New session, reset timers")
            self._timeout = 1
            self._last_fail_time = None
        return response

