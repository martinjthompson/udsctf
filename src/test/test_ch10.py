import logging
import pytest
import time
from base64 import b64decode
from binascii import hexlify

import udsoncan
from . test_ch00 import client_ecu, Flag_string_codec

from .. vecu.vecu10 import Vecu10

def test_challenge10():
    challenge = 10
    session = 0x60
    security_level = 0x3
    log = logging.getLogger()
    log.info("Start")

    (client,ecu) = client_ecu(Vecu10)
    log.info("Client and ECU setup")
    client.set_config('data_identifiers', {challenge:Flag_string_codec})
    log.setLevel(logging.INFO)

    # TODO - refactor, we will probably be doing this a lot!
    # log.info("check read DID in default session rejected")
    # with pytest.raises(udsoncan.exceptions.NegativeResponseException):
    #     _=client.read_data_by_identifier(challenge)
    # log.info("check read DID in session out of security rejected")
    # client.change_session(session)
    # with pytest.raises(udsoncan.exceptions.NegativeResponseException):
    #     flag = client.read_data_by_identifier(challenge)

    # log.info("check incorrect key rejected")
    # client.change_session(session)
    # uds_seed = client.request_seed(security_level)
    # uds_key = bytes([x^0xFE for x in uds_seed.data[1:]])
    # with pytest.raises(udsoncan.exceptions.NegativeResponseException):
    #     client.send_key(security_level+1, uds_key)

    log.info("Check we can find the key")
    client.change_session(session)
    uds_key = bytearray([0]*4)
    times = [0] * 256
    for bytenum in range (4):
        for val in range(256):
            uds_key[bytenum] = val

            # we don't care what the seed is
            _ = client.request_seed(security_level).data[1:]
            t = time.time()
            log.info("Key trial:%s", hexlify(uds_key))
            try:
                client.send_key(security_level+1, bytes(uds_key))
            except udsoncan.exceptions.NegativeResponseException:
                delta_t = time.time() - t
                times[val]  = delta_t
                continue
            # we got it right!
            break

        _, idx = min((val, idx) for (idx, val) in enumerate(times))
        uds_key[bytenum] = idx

    flag = client.read_data_by_identifier(challenge)
    assert(flag.data[2:] == b64decode(ecu._dids[challenge]))
    ecu.stop()
    log.info("end")     
