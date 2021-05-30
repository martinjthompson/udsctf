import logging
import pytest
import time
from base64 import b64decode
from binascii import hexlify

import udsoncan
from udsoncan import Response

from . test_base import logging_setup
from . test_ch00 import client_ecu, Flag_string_codec

from .. vecu.vecu16 import Vecu16

challenge = 16
session = 0x60
security_level = 0x3
log = logging_setup()

def s():
    log.info("Setup")

    (client,ecu) = client_ecu(Vecu16)
    client.set_config('data_identifiers', {challenge:Flag_string_codec})
    log.setLevel(logging.INFO)
    return client, ecu
    ecu.stop()

def test_challenge16a():
    client,ecu = s()

    log.info("Trigger escalating timeout by sending wrong key")
    _  = client.change_session(session)
    _ = client.request_seed(security_level)
    with pytest.raises(udsoncan.exceptions.NegativeResponseException):
        _ = client.send_key(security_level+1, b'\x00')

    log.info("Check we get rejected asking for another seed, even after a reset")
    _ = client.ecu_reset(1)
    _  = client.change_session(session)
    try:
        resp = client.request_seed(security_level)
        assert(resp.code != Response.Code.PositiveResponse)
    except udsoncan.exceptions.NegativeResponseException as e:
        log.info("Rejected: %s", e)
        assert(e.response.code == Response.Code.RequiredTimeDelayNotExpired)
    ecu.stop()

def test_challenge16b():
    client, ecu = s()
    log.info("Check we can find the key")
    trial_key = b'\x01'
    while 1: 
        _ = client.change_session(0x03) # reset timers
        _ = client.change_session(session)
        _ = client.request_seed(security_level)
        log.info("Trial")
        try:
            resp = client.send_key(security_level, trial_key)
        except udsoncan.exceptions.NegativeResponseException as e:
            if e.response.code != Response.Code.SecurityAccessDenied:
                log.error(e)
                raise
            continue
        if resp.code == Response.Code.PositiveResponse:
            break
    assert(ecu._uds_key == trial_key)

    flag = client.read_data_by_identifier(challenge)
    assert(flag.data[2:] == b64decode(ecu._dids[challenge]))
    ecu.stop()
    
    