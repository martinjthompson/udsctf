import logging
import pytest
import time
from base64 import b64decode
from binascii import hexlify

import udsoncan
from udsoncan import Response

from . test_ch00 import client_ecu, Flag_string_codec

from .. vecu.vecu20 import Vecu20

challenge = 20
session = 0x60
security_level = 0x3
log = logging.getLogger()

def calc_key_from_seed(seed):
    key = bytearray()
    for s in seed:
        key.append(s^0x35)

    return bytes(key)

def test_challenge20():
    (client,ecu) = client_ecu(Vecu20)
    client.set_config('data_identifiers', {challenge:Flag_string_codec})
    log.setLevel(logging.INFO)
    try:
        flag = client.read_data_by_identifier(challenge)
    except:
        pass
    assert("flag" not in locals())
    log.critical("Start")
    _ = client.change_session(0x03) # reset timers
    _ = client.change_session(session)
    log.critical("Req Seed")
    seed = client.request_seed(security_level).data[1:]
    log.info("Seed: %s", hexlify(seed))
    trial_key = calc_key_from_seed(seed)
    log.info("TKey: %s", hexlify(trial_key))
    _ = client.send_key(security_level, trial_key)

    assert(ecu._uds_key == trial_key)

    flag = client.read_data_by_identifier(challenge)
    assert(flag.data[2:] == b64decode(ecu._dids[challenge]))
    ecu.stop()
    
    