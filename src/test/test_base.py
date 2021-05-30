import colorlog
import logging
import can
from .. vecu.vecu import Vecu

import udsoncan
from udsoncan.client import Client
from udsoncan.exceptions import NegativeResponseException,InvalidResponseException,UnexpectedResponseException

def logging_setup():
    print ("Setup")
    handler = colorlog.StreamHandler()
    handler.setFormatter(colorlog.ColoredFormatter('%(log_color)s%(levelname)8s:%(name)25s:%(message)s'))

    logger = colorlog.getLogger()
    logger.handlers = []
    logger.addHandler(handler)
    return logger

def test_basic_uds():
    log = logging_setup()
    log.setLevel(logging.DEBUG)
    log.info("Start")
    ecu = Vecu()
    ecu.log.setLevel(logging.DEBUG)
    conn = ecu.get_connection()
    log.info('Connection opened')
    with Client(conn,  request_timeout=2, config=ecu.config) as client:
        log.info("Read VIN")
        try:
            # Standard ID for VIN is 0xF190. Codec is set in the client configuration which comes from the ECU in this test
            vin = client.read_data_by_identifier(udsoncan.DataIdentifier.VIN)       
            print("Read VIN: %s %s"%(vin, vin.data))
            assert(vin.data[2:] == ecu.vin)
        except NegativeResponseException as e:
            log.error('Server refused our request for service %s with code "%s" (0x%02x)' , e.response.service.get_name(), e.response.code_name, e.response.code)
            raise
        except (InvalidResponseException, UnexpectedResponseException) as e:
            log.error('Server sent an invalid payload : %s' , e.response.original_payload)
            raise
    log.info('Stopping ECU')
    ecu.stop()
            