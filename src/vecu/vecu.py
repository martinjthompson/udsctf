import time
import struct
import time
import logging
from threading import Thread

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

                    # Read Data By identifier
                    elif req.service == services.ReadDataByIdentifier:
                        response = Response(req.service, Response.Code.RequestOutOfRange)
                        try:
                            id = struct.unpack('>h', req.data)
                            if id == DataIdentifier.VIN:
                                response = Response(req.service, Response.Code.PositiveResponse, data=self.vin)
                        except ValueError:
                            pass

                    # # Write Data By identifier
                    # elif req.service == services.WriteDataByIdentifier:
                    #     if req.data[0:2] in [b"\x00\x01", b"\x00\x02", b"\x00\x03", b'\xF1\x90']:
                    #         response = Response(
                    #             req.service, Response.Code.PositiveResponse, req.data[0:2])
                    #     else:
                    #         response = Response(
                    #             req.service, Response.Code.RequestOutOfRange)

                    else:
                        response = Response(
                            req.service, Response.Code.ServiceNotSupported)

                    if not response.positive or not req.suppress_positive_response:
                        self.conn.send(response)
                    else:
                        print("Suppressing positive response.")
