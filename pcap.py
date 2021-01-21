import struct
import time


class Pcap:

    def __init__(self, filename, linkType=1): # Constructor crate file with filename 
        self.pcapFile = open(filename, 'wb') # Open file
        self.pcapFile.write(struct.pack('@ I H H i I I I', 0xa1b2c3d4, 2, 4, 0, 0, 65535, linkType)) # Prepares the pcap file according to the given format
    # Below block writes on the .pcap file
    def write(self, data):
        tsSec, tsUsec = map(int, str(time.time()).split('.')) # Update time row according to current time
        length = len(data) # Get data length from data packet
        self.pcapFile.write(struct.pack('@ I I I I', tsSec, tsUsec, length, length)) # Add the values in to the pcap file according to given format 
        self.pcapFile.write(data) # Add the data in the content of the packet

    def close(self):
        self.pcapFile.close() # Close created pcap file
