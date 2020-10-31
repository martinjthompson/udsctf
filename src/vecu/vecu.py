import time
import struct
import time
import logging
from threading import Thread
from base64 import b64encode, b64decode

import udsoncan
from udsoncan import configs, services, Request, Response, DidCodec, DataIdentifier
from udsoncan.connections import QueueConnection

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
        self.log = logging.getLogger('Vecu')
        self.log.setLevel(logging.INFO)
        self.vin=b"THIS_IS_A_VIN_123"
        self.config = dict(configs.default_client_config)
        self.config['data_identifiers'] = {DataIdentifier.VIN:VIN_Codec}
        self.conns = SimulatedConnections('Q')
        self.conn = self.conns.server_connection

        self.__stop = False
        self.last_msg_time = time.time()
        self.log.info("Init complete, starting background thread")
        self.session = udsoncan.services.DiagnosticSessionControl.Session.defaultSession
        self._flags = {0:b'KiogUGlhbm9Gb3J0ZSAqKg==', 1:b'LS0tU2F4b3Bob25lIC0tLQ=='}
        self.start()
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
                payload = self.conn.wait_frame(timeout=1, exception=True )
                if payload is None:
                    delta =  time.time() - self.last_msg_time 
                    if delta > 3:
                        self.log.warning("No messages for %f sec, exiting", delta)
                        break
                else:
                    req = Request.from_payload(payload)
                    self.log.debug(req)
                    response = Response(req.service, Response.Code.GeneralReject)
                    
                    # Tester present
                    if req.service == services.TesterPresent:
                        response = Response(req.service, Response.Code.PositiveResponse)
                    # DiagnosticSessionControl
                    elif req.service == services.DiagnosticSessionControl:
                        if req.subfunction == services.DiagnosticSessionControl.Session.extendedDiagnosticSession:
                            response = Response(req.service, Response.Code.PositiveResponse, 
                                                data=struct.pack('>bHH', req.subfunction, 1000, 100))
                            self.session = req.subfunction
                        else:
                            response = Response(req.service, Response.Code.SubFunctionNotSupported)                        
                    # Read Data By identifier
                    elif req.service == services.ReadDataByIdentifier:
                        response = Response(req.service, Response.Code.RequestOutOfRange)
                        try:
                            id = struct.unpack('>H', req.data)[0]
                            self.log.debug('Read DID %u', id)
                            if id == DataIdentifier.VIN:
                                response_data = self.vin
                            elif id in self._flags:
                                response_data = None
                                if (id == 00 or
                                   (id == 0x0001 and self.session == 3)):
                                    response_data = b64decode(self._flags[id])
                            if response_data is not None:
                                response = Response(req.service, Response.Code.PositiveResponse, data=req.data+response_data)
                        except ValueError:
                            pass
                    else:
                        response = Response(req.service, Response.Code.ServiceNotSupported)

                    if not response.positive or not req.suppress_positive_response:
                        self.log.debug("Response:%s (data:%s)", response, response.data)
                        self.conn.send(response)
                    else:
                        print("Suppressing positive response.")
