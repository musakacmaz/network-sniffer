import textwrap
import socket
import struct

class Ethernet:
    # Constructor of the ethernet packet accorging to raw data
    def __init__(self, rawData): 

        dest, src, prototype = struct.unpack('! 6s 6s H', rawData[:14]) # Parses the incoming packet according to ethernet format
        # Below block fills the ethernet objects
        self.destMac = getMacAddress(dest)
        self.srcMac = getMacAddress(src)
        self.proto = socket.htons(prototype)
        self.data = rawData[14:]



# Below function returns MAC as string from bytes (ie AA:BB:CC:DD:EE:FF)
def getMacAddress(macRaw):
    byteStr = map('{:02x}'.format, macRaw)
    macAddr = ':'.join(byteStr).upper()
    return macAddr


# Below function formats multi-line data
def formatMultiLine(prefix, sg, size=80):
    size -= len(prefix)
    if isinstance(sg, bytes):
        sg = ''.join(r'\x{:02x}'.format(byte) for byte in sg)
        if size % 2:
            size -= 1
    return '\n'.join([prefix + line for line in textwrap.wrap(sg, size)])
