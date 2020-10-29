import logging
import can
from .. vecu.vecu import Vecu

import udsoncan
from udsoncan.client import Client
from udsoncan.exceptions import NegativeResponseException,InvalidResponseException,UnexpectedResponseException

def test_basic_uds():
    logging.basicConfig(level=logging.DEBUG)
    udsoncan.setup_logging()
    log = logging.getLogger()
    log.setLevel(logging.DEBUG)
    log.info("Start")
    ecu = Vecu()
    ecu.log.setLevel(logging.DEBUG)
    conn = ecu.get_connection()
    log.info('Connection opened')
    with Client(conn,  request_timeout=2, config=ecu.config) as client:
        try:
            # Standard ID for VIN is 0xF190. Codec is set in the client configuration which comes from the ECU in this test
            vin = client.read_data_by_identifier(udsoncan.DataIdentifier.VIN)       
            print("Read VIN: %s", vin)
            assert(vin == ecu.vin)
        except NegativeResponseException as e:
            print('Server refused our request for service %s with code "%s" (0x%02x)' % (e.response.service.get_name(), e.response.code_name, e.response.code))
        except (InvalidResponseException, UnexpectedResponseException) as e:
            print('Server sent an invalid payload : %s' % e.response.original_payload)
    log.info('Stopping ECU')
    ecu.stop()
            