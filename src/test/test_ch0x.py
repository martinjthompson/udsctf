import pytest
import logging
from base64 import b64decode

import udsoncan
import udsoncan.client

from .. vecu.vecu import Vecu

class Flag_string_codec(udsoncan.DidCodec):
    def encode(self, s):
        return bytes(s.encode('ascii'))
    def decode(self, b):
        return b.decode('ascii')
    def __len__(self):
        return 16

@pytest.fixture()
def client_ecu():
    print ("Setup")
    udsoncan.setup_logging()
    ecu = Vecu()
    ecu.log.setLevel(logging.DEBUG)
    config = dict(udsoncan.configs.default_client_config)
    with udsoncan.client.Client(ecu.get_connection(),  request_timeout=2, config=config) as client:
        yield (client,ecu)
    print ("Teardown")
    ecu.stop()

def test_challenge00(client_ecu):
    (client,ecu) = client_ecu
    client.set_config('data_identifiers', {0x0000:Flag_string_codec})
    flag = client.read_data_by_identifier(0x0000)  
    assert(flag.data[2:] == b64decode(ecu._flags[0]))
            
def test_challenge01(client_ecu):
    (client,ecu) = client_ecu
    client.set_config('data_identifiers', {0x0001:Flag_string_codec})
    with pytest.raises(udsoncan.exceptions.NegativeResponseException):
        client.read_data_by_identifier(0x0001)
    with pytest.raises(udsoncan.exceptions.NegativeResponseException):
        client.change_session(0x7F)
    # check OK
    client.change_session(udsoncan.services.DiagnosticSessionControl.Session.extendedDiagnosticSession)
    flag = client.read_data_by_identifier(0x0001)
    assert(flag.data[2:] == b64decode(ecu._flags[1]))
