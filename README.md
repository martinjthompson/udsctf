# UDSCTF

A collection of capture-the-flag style challenges based around the [Unified Diagnostic Standard (UDS)](https://en.wikipedia.org/wiki/Unified_Diagnostic_Services). No knowledge of UDS is assumed. The [library used in this project has some good documentation](https://udsoncan.readthedocs.io/en/latest/udsoncan/intro.html).

The setup is of a virtual electronic control unit (ECU) which responds to UDS messages in a manner seen in real ECUs.  The goal of each challenge is extract a flag value from the ECU. The different flags for the different levels are protected by the UDS standard challenge response protocol (which is called "seed and key" in the industry parlance - do not confuse these terms with their usual computer science/cryptography meanings - they map directly to "challenge" and "response").

## UDS
UDS consists of a Client (which is you) and a Server (which is the ECU you are accessing).  The Client initiates a transaction with the Server. The Server responds with either some data or an error code (termed a Negative Response Code).  The Server will offer a variety of "sessions" each of which provide a variety of "services".  We will introduce them as required :) A useful list of services and response codes can be found on the [Automotive Wiki](https://automotive.wiki/index.php/ISO_14229).

### DIDs

One widely used service is to read a Data IDentifier, which is abbreviated to DID. Each DID is addressed by a 16-bit number.  The flag for each challenge is obtained by reading DID number associated with the challenge

The content of a DID in a real ECU may or may not be documented publically.  There is a configuration for the UDS Client which you will have to fill out to correctly decode the flags from the DIDs. For simplicity all the flags in these challenges will be 16 ASCII characters.


## Installation

The code is all Python 3.x.  It uses the open source [udsoncan](https://github.com/pylessard/python-udsoncan) library to provide abstract access to the details of the UDS messaging. Install the required libraries into your preferred virtual environment with

```
pip install -r requirements.txt
```

Check all is well using `pytest`.

## The challenges

You can find the challenges in the `challenges` subdirectory.  
