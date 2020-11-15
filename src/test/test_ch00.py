import pytest
import logging
from base64 import b64decode
from binascii import hexlify

import udsoncan
import udsoncan.client

from .. vecu.vecu00 import Vecu00

class Flag_string_codec(udsoncan.DidCodec):
    def encode(self, s):
        return bytes(s.encode('ascii'))
    def decode(self, b):
        return b.decode('ascii')
    def __len__(self):
        return 16

def client_ecu(EcuClass):
    logging.debug("Setup:%s", EcuClass)
    # udsoncan.setup_logging()
    ecu = EcuClass()
    ecu.log.setLevel(logging.DEBUG)
    config = dict(udsoncan.configs.default_client_config)
    client = udsoncan.client.Client(ecu.get_connection(),  request_timeout=2, config=config)
    client.__enter__()
    logging.debug("Client: %s", client)
    return (client,ecu)

def test_challenge00():
    (client,ecu) = client_ecu(Vecu00)
    client.set_config('data_identifiers', {0x0000:Flag_string_codec})
    flag = client.read_data_by_identifier(0x0000)  
    assert(flag.data[2:] == b64decode(ecu._dids[0]))
    ecu.stop()            
