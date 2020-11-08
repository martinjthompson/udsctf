import pytest
import logging
from base64 import b64decode
from binascii import hexlify

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

def test_challenge02(client_ecu):
    log = logging.getLogger("ch02")
    log.setLevel(logging.DEBUG)
    log.info("Start")
    (client,ecu) = client_ecu
    security_level = 0x3
    client.set_config('data_identifiers', {0x0002:Flag_string_codec})

    log.info("check read DID in default session rejected")
    with pytest.raises(udsoncan.exceptions.NegativeResponseException):
        _=client.read_data_by_identifier(0x0002)
    log.info("check read DID in session out of security rejected")
    client.change_session(0x60)
    with pytest.raises(udsoncan.exceptions.NegativeResponseException):
        flag = client.read_data_by_identifier(0x0002)
    log.info("check out of sequence key rejected")
    client.change_session(0x60)
    with pytest.raises(udsoncan.exceptions.NegativeResponseException):
        client.send_key(security_level, b'00000000')

    log.info("check incorrect key rejected")
    client.change_session(0x60)
    uds_seed = client.request_seed(security_level)
    uds_key = bytes([x^0xFE for x in uds_seed.data[1:]])
    with pytest.raises(udsoncan.exceptions.NegativeResponseException):
        client.send_key(security_level+1, uds_key)

    log.info("Check correct key accepted")
    client.change_session(0x60)
    uds_seed = client.request_seed(security_level)
    uds_key = bytes([x^0xFF for x in uds_seed.data[1:]])
    client.send_key(security_level+1, uds_key)
    flag = client.read_data_by_identifier(0x0002)
    assert(flag.data[2:] == b64decode(ecu._flags[2]))
    log.info("end")    
