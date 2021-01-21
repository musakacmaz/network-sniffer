import struct


class IPv4:
    #below block is the constructor of the ipv4
    def __init__(self, rawData):
        versionHeaderLength = rawData[0]
        self.version = versionHeaderLength >> 4
        self.headerLength = (versionHeaderLength & 15) * 4
        self.ttl, self.proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', rawData[:20]) #first 20 characters of the raw data is assigned to objects
        self.src = self.ipv4(src) #initialize
        self.target = self.ipv4(target)
        self.data = rawData[self.headerLength:]

    # Returns properly formatted IPv4 address
    def ipv4(self, addr):
        return '.'.join(map(str, addr))



class TCP:

    #constructor of the tcp packet
    def __init__(self, rawData):
        (self.srcPort, self.destPort, self.sequence, self.acknowledgment, offsetReservedFlags) = struct.unpack(
            '! H H L L H', rawData[:14]) #according to the first 14 characters, offset reserved flags are added
        offset = (offsetReservedFlags >> 12) * 4
        self.flagUrg = (offsetReservedFlags & 32) >> 5
        self.flagAck = (offsetReservedFlags & 16) >> 4
        self.flagPsh = (offsetReservedFlags & 8) >> 3
        self.flagRst = (offsetReservedFlags & 4) >> 2
        self.flagSyn = (offsetReservedFlags & 2) >> 1
        self.flagFin = offsetReservedFlags & 1
        self.data = rawData[offset:]



class HTTP:
    #http data constructor created
    def __init__(self, rawData):
        try:
            self.data = rawData.decode('utf-8')
        except:
            self.data = rawData


