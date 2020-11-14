import pytest
from base64 import b64decode

import udsoncan
from .. vecu.vecu01 import Vecu01

from . test_ch00 import client_ecu, Flag_string_codec

def test_challenge01():
    (client,ecu) = client_ecu(Vecu01)
    client.set_config('data_identifiers', {0x0001:Flag_string_codec})
    with pytest.raises(udsoncan.exceptions.NegativeResponseException):
        client.read_data_by_identifier(0x0001)
    with pytest.raises(udsoncan.exceptions.NegativeResponseException):
        client.change_session(0x7F)
    # check OK
    client.change_session(udsoncan.services.DiagnosticSessionControl.Session.extendedDiagnosticSession)
    flag = client.read_data_by_identifier(0x0001)
    assert(flag.data[2:] == b64decode(ecu._dids[1]))
    ecu.stop()
