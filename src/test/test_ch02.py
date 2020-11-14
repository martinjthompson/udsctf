import logging
import pytest
from base64 import b64decode

import udsoncan
from . test_ch00 import client_ecu, Flag_string_codec

from .. vecu.vecu02 import Vecu02

def test_challenge02():
    log = logging.getLogger("ch02")
    log.setLevel(logging.DEBUG)
    log.info("Start")

    (client,ecu) = client_ecu(Vecu02)
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
    assert(flag.data[2:] == b64decode(ecu._dids[2]))
    ecu.stop()
    log.info("end")    
