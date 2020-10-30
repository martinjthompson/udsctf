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


def test_challenge00():
    udsoncan.setup_logging()
    ecu = Vecu()
    ecu.log.setLevel(logging.DEBUG)
    config = dict(udsoncan.configs.default_client_config)
    config['data_identifiers'] = {0x0000:Flag_string_codec}
    with udsoncan.client.Client(ecu.get_connection(),  request_timeout=2, config=config) as client:
        flag = client.read_data_by_identifier(0x0000)  
        print (flag, flag.data)     
        assert(flag.data[2:] == b64decode(ecu._flags[0]))
    ecu.stop()
            