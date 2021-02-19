import time
import struct
import time
import logging
from threading import Thread
from base64 import b64encode, b64decode
import secrets
from binascii import hexlify

import udsoncan
from udsoncan import configs, services, Request, Response, DidCodec, DataIdentifier
from udsoncan.connections import QueueConnection
from udsoncan.exceptions import TimeoutException
from . simulated_connection import SimulatedConnections

class VIN_Codec(DidCodec):
    def encode(self, s):
        return bytes(s.encode('ascii'))
    def decode(self, b):
        return b.decode('ascii')
    def __len__(self):
        return 17

class Vecu(Thread):
    def __init__(self):
        Thread.__init__(self)
        self.log = logging.getLogger(type(self).__name__)
        self.log.setLevel(logging.INFO)
        self.vin=b"THIS_IS_A_VIN_123"
        self.config = dict(configs.default_client_config)
        self.config['data_identifiers'] = {DataIdentifier.VIN:VIN_Codec}
        self.conns = SimulatedConnections('Q')
        self.conn = self.conns.server_connection

        self.__stop = False
        self.last_msg_time = time.time()
        self.log.info("Init complete, starting background thread")
        self._dids = {}
        self.session = udsoncan.services.DiagnosticSessionControl.Session.defaultSession
        self.reset()
        self.start()

    def reset(self):
        self.session = udsoncan.services.DiagnosticSessionControl.Session.defaultSession
        self.security_level = 0
        self.security_level_request = None
        self.seed_store = None

    def get_connection(self):
        return self.conns.client_connection
    def stop(self):
        self.log.info('Stop')
        self.__stop = True
        self.join()
    def __del__(self):
        self.stop()
    def run(self):
        self.log.info('Thread started')
        with self.conn.open():
            self.log.info('connection opened')
            while True:
                if self.__stop:
                    break
                try:
                    payload = self.conn.wait_frame(timeout=1, exception=True)
                except TimeoutException:
                    payload = None
                if payload is None:
                    delta =  time.time() - self.last_msg_time 
                    if delta > 2.0:
                        self.log.warning("No messages for %f sec, exiting", delta)
                        break
                else:
                    req = Request.from_payload(payload)
                    self.log.debug(req)
                    response = self.handle(req)
                    if response is None:
                        self.log.warning("Service  0x%04x not supported", req.service)
                        response = Response(req.service, Response.Code.ServiceNotSupported)

                    if not response.positive or not req.suppress_positive_response:
                        self.log.debug("Response:%s (data:%s)", response, response.data)
                        self.conn.send(response)
                    else:
                        self.log.info("Suppressing positive response.")

    def is_session_allowed(self, session):
        return session in (services.DiagnosticSessionControl.Session.extendedDiagnosticSession,0x60)

    def diagnostic_session_control(self, req):
        if self.is_session_allowed(req.subfunction):
            response = Response(req.service, Response.Code.PositiveResponse, data=struct.pack('>bHH', req.subfunction, 1000, 100))
            self.session = req.subfunction
            self.security_level = 0
            self.log.info("Changed session to 0x%02x", self.session)
        else:
            self.log.error("Session 0x%02x not valid", req.subfunction)
            response = Response(req.service, Response.Code.SubFunctionNotSupported)                        
        return response

    def is_read_did_allowed(self, id):
        return False
        
    def read_did(self, req):
        response = Response(req.service, Response.Code.RequestOutOfRange)
        id = struct.unpack('>H', req.data)[0]
        self.log.debug('Read DID 0x%04x', id)
        response_data = None
        if id == DataIdentifier.VIN:
            response_data = self.vin
        elif self.is_read_did_allowed(id):
            response_data = b64decode(self._dids[id])
        if response_data is not None:
            self.log.info("Read DID 0x%04x allowed in session 0x%02X security level 0x%02X -> %s", id, self.session, self.security_level, str(response_data))
            response = Response(req.service, Response.Code.PositiveResponse, data=req.data+response_data)
        else:
            self.log.warning("Read DID 0x%04x not allowed in session 0x%02X security level 0x%02X", id, self.session, self.security_level)

        return response

    def ecu_reset(self, req):
        self.reset()
        response = Response(req.service, Response.Code.PositiveResponse, data=bytes([req.subfunction]))
        return response

    def _request_seed(self, security_level):
        return None

    def _expected_key(self, security_level):
        return None

    def _compare(self, got, expected):
        return got == expected

    def handle(self, req):
        response = None
        
        if req.service == services.TesterPresent:
            response = Response(req.service, Response.Code.PositiveResponse, bytes([req.subfunction]))
        elif req.service == services.DiagnosticSessionControl:
            response = self.diagnostic_session_control(req)
        elif req.service == services.ReadDataByIdentifier:
            response = self.read_did(req)
        elif req.service == services.ECUReset:
            response = self.ecu_reset(req)
        # Security Access - TODO make into function
        elif req.service == services.SecurityAccess:
            security_level = req.subfunction
            seed = None
            if (security_level & 1 == 1): # Client is requesting seed
                response = Response(req.service, Response.Code.RequestOutOfRange)
                seed = self._request_seed(security_level)
                if type(seed) == Response:
                    response = seed
                elif seed is not None:
                    response = Response(req.service, Response.Code.PositiveResponse, data=bytes([security_level])+seed)
                    self.log.info("Session 0x%02x security level 0x%02x seed = %s", self.session, security_level, hexlify(seed))
                    self.seed_store = seed
                    self.security_level_request = security_level
            else: # Client has sent key
                response = Response(req.service, Response.Code.GeneralReject)
                if (self.security_level_request is None) or (security_level != self.security_level_request+1):
                    if self.seed_store is None:
                        self.log.error("Sequence error - no seed requested")
                    else:
                        self.log.error("Sequence error - wrong security level")
                    self.seed_store = None
                    self.security_level_request = None
                    response = Response(req.service, Response.Code.RequestSequenceError)
                else:
                    response = Response(req.service, Response.Code.SecurityAccessDenied)
                    key = req.data
                    expected_key = self._expected_key(security_level)
                    
                    if self._compare(key, expected_key):
                        self.log.info("Key received %s correctly", hexlify(key))
                        response = Response(req.service, Response.Code.PositiveResponse, data=bytes([security_level]))
                        self.security_level = self.security_level_request
                    else:
                        self.log.warning("Key received %s incorrectly", hexlify(key))
                    self.seed_store = None
                    self.security_level_request = None

        return response
