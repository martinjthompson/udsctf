import logging
import pytest
from base64 import b64decode

import udsoncan
from . test_ch00 import client_ecu, Flag_string_codec

from .. vecu.vecu05 import Vecu05

def test_challenge05():
    challenge = 0x0005
    session = 0x60
    security_level = 0x3
    log = logging.getLogger()
    log.info("Start")

    (client,ecu) = client_ecu(Vecu05)
    log.info("Client and ECU setup")
    client.set_config('data_identifiers', {challenge:Flag_string_codec})
    log.setLevel(logging.INFO)

    # TODO - refactor, we will probably be doing this a lot!
    log.info("check read DID in default session rejected")
    with pytest.raises(udsoncan.exceptions.NegativeResponseException):
        _=client.read_data_by_identifier(challenge)
    log.info("check read DID in session out of security rejected")
    client.change_session(session)
    with pytest.raises(udsoncan.exceptions.NegativeResponseException):
        flag = client.read_data_by_identifier(challenge)

    log.info("check incorrect key rejected")
    client.change_session(session)
    uds_seed = client.request_seed(security_level)
    uds_key = bytes([x^0xFE for x in uds_seed.data[1:]])
    with pytest.raises(udsoncan.exceptions.NegativeResponseException):
        client.send_key(security_level+1, uds_key)

    log.info("Check correct key accepted")
    client.change_session(0x60)
    while 1:
        uds_seed = client.request_seed(security_level).data[1:]
        log.info("Seed:%s", uds_seed)
        if uds_seed == b'Ky':
            break
    uds_key = b'OK'
    client.send_key(security_level+1, uds_key)
    flag = client.read_data_by_identifier(challenge)
    assert(flag.data[2:] == b64decode(ecu._dids[challenge]))
    ecu.stop()
    log.info("end")    
