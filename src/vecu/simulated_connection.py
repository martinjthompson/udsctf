import queue
from udsoncan.connections import BaseConnection
from udsoncan.exceptions import TimeoutException

class SimulatedConnection(BaseConnection):
    """
    Sends and receives data using 2 Python native queues.

    - ``MyConnection.rxq`` : Data read from this queue when ``wait_frame`` is called . 
    - ``MyConnection.txq`` : Data written to this queue when ``send`` is called .

    :param mtu: Optional maximum frame size. Messages will be truncated to this size
    :type mtu: int
    :param name: This name is included in the logger name so that its output can be redirected. The logger name will be ``Connection[<name>]``
    :type name: string

    """
    def __init__(self, txq, rxq, name=None, mtu=4095):
        BaseConnection.__init__(self, name)
        self.txq = txq
        self.rxq = rxq
        self.opened = False
        self.mtu = mtu

    def open(self):
        self.opened = True
        self.logger.info('Connection opened')
        return self

    def __enter__(self):
        return self

    def __exit__(self, type, value, traceback):
        self.close()

    def is_open(self):
        return self.opened 

    def close(self):
        self.empty_rxqueue()
        self.empty_txqueue()
        self.opened = False
        self.logger.info('Connection closed')	

    def specific_send(self, payload):
        if self.mtu is not None:
            if len(payload) > self.mtu:
                self.logger.warning("Truncating payload to be set to a length of %d" % (self.mtu))
                payload = payload[0:self.mtu]

        self.txq.put(payload)
        
    def specific_wait_frame(self, timeout=2):
        if not self.opened:
            raise RuntimeError("Connection is not open")

        timedout = False
        frame = None

        try:
            frame = self.rxq.get(block=True, timeout=timeout)
        except queue.Empty:
            timedout = True

        if timedout:
            raise TimeoutException("Did not receive frame from queue in time (timeout=%s sec)" % (timeout))

        if self.mtu is not None:
            if frame is not None and len(frame) > self.mtu:
                self.logger.warning("Truncating received payload to a length of %d" % (self.mtu))
                frame = frame[0:self.mtu]

        return frame

    def empty_rxqueue(self):
        while not self.rxq.empty():
            self.rxq.get()

    def empty_txqueue(self):
        while not self.txq.empty():
            self.txq.get()

class SimulatedConnections():
    def __init__(self, name=""):
        fromclientq = queue.Queue()
        toclientq = queue.Queue()
        self.client_connection = SimulatedConnection(fromclientq, toclientq, name+"(Client)")
        self.server_connection = SimulatedConnection(toclientq, fromclientq, name+"(Server)")