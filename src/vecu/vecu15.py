from time import time
import secrets

from . vecu import Vecu
from udsoncan import Response, services

class Vecu15(Vecu):
    def __init__(self):
        super(Vecu15, self).__init__()
        self._target_did = 15
        self._dids[self._target_did] = b'LT0tIFBpY2NvbG8gIC09LQ=='
        self._target_session = 0x60
        self._target_level = 3
    
    def reset(self):
        super(Vecu15, self).reset()
        self._timeout = 1
        self._last_fail_time = None

    def is_read_did_allowed(self, id):
        if id == self._target_did and self.session == self._target_session and self.security_level == self._target_level:
            return True
        return False

    def _is_timeout_ok(self):
        now = time()
        if self._last_fail_time is not None:
            delta = now - self._last_fail_time 
        else:
            delta = None
        self.log.debug("Timeouts: %12f %s %s %12f", now, str(self._last_fail_time), str(delta), self._timeout)
        if self._last_fail_time is not None and delta < self._timeout:
            return False
        return True

    def _request_seed(self, security_level):
        if not self._is_timeout_ok():
            self.log.error("Seed requested too soon")
            return Response(services.SecurityAccess, Response.Code.RequiredTimeDelayNotExpired)

        if self.session == self._target_session and security_level == self._target_level: 
            self._uds_seed = secrets.token_bytes(1)
            while 1:
                self._uds_key = secrets.token_bytes(1)
                if self._uds_key != b'\x00': # this means we can use 0000 intesting to definitely fail
                    break
            self.log.info("Seed = %s Key = %s", self._uds_seed, self._uds_key)
            return self._uds_seed
        return None

    def _expected_key(self, security_level):
        if security_level == self._target_level+1:
            return self._uds_key
        return None

    def _compare(self, got, expected):
        if got != expected:
            self._timeout *= 2
            _ = self._is_timeout_ok() # we do not care about the result, but want the side effect of logging the last attempt
            self._last_fail_time = time()
        else:
            self._last_fail_time = None
            self._timeout = 1

        return got == expected
