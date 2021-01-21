import socket
import time
import sys
from ethernet import *
from ipv4 import *
from pcap import Pcap


TAB_1 = '\t - '
TAB_2 = '\t\t - '
TAB_3 = '\t\t\t - '
TAB_4 = '\t\t\t\t - '

DATA_TAB_1 = '\t   '
DATA_TAB_2 = '\t\t   '
DATA_TAB_3 = '\t\t\t   '
DATA_TAB_4 = '\t\t\t\t   '



# Below block main function of program to run
def main():
    pcap = Pcap(sys.argv[1] + '.pcap') # Desired file name without .pcap extention from user(terminal) 
    packet = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3)) # - New socket is opened and program starts to listen
                                                                               # - ntohs() function converts the unsigned short integer netshort
                                                                               # from network byte order tohost byte order.
    
    # Program finish time added
    programStarts = time.time() + int(sys.argv[2]) # Desired loop(running) time gettimg from user(terminal)
    now = time.time() # Initialize control now time
    # Belong block system loop runs until end time

    count = 0
    while now < programStarts:
        now = time.time() # For upgrade time each packet


        rawData, addr = packet.recvfrom(65535) # For receive data from the socket.(String, Address)
        pcap.write(rawData) # Received data is writing to the .pcap file.
        eth = Ethernet(rawData) # Create ethernet object according to raw data

        print('\nEthernet Frame:')
        print(TAB_1 + 'Destination: {}, Source: {}, Protocol: {}'.format(eth.destMac, eth.srcMac, eth.proto)) # - Print source and destination MAC addess,
                                                                                                              # protocol of the packet.

        # Below block IPv4 version 
        if eth.proto == 8: # Checks the protocol number of IPv4 version from ethernet
            ipv4 = IPv4(eth.data) # Create IPv4 object according to ethernet data
            # Below block displays information of IPv4 packet on screen
            print(TAB_1 + 'IPv4 Packet:')
            print(TAB_2 + 'Version: {}, Header Length: {}, TTL: {},'.format(ipv4.version, ipv4.headerLength, ipv4.ttl))
            print(TAB_2 + 'Protocol: {}, Source: {}, Target: {}'.format(ipv4.proto, ipv4.src, ipv4.target))

            count += 1 #total packet number increases


            # Below block TCP packet
            if ipv4.proto == 6: # Checks the protocol number of TCP packet from IPv4
                tcp = TCP(ipv4.data) # Create TCP object according to IPv4 data
                # Below block displays information of TCP packet on screen
                print(TAB_1 + 'TCP Segment:')
                print(TAB_2 + 'Source Port: {}, Destination Port: {}'.format(tcp.srcPort, tcp.destPort))
                print(TAB_2 + 'Sequence: {}, Acknowledgment: {}'.format(tcp.sequence, tcp.acknowledgment))
                print(TAB_2 + 'Flags:')
                print(TAB_3 + 'URG: {}, ACK: {}, PSH: {}'.format(tcp.flagUrg, tcp.flagAck, tcp.flagPsh))
                print(TAB_3 + 'RST: {}, SYN: {}, FIN:{}'.format(tcp.flagRst, tcp.flagSyn, tcp.flagFin))

                if len(tcp.data) > 0: # If there is any data print it on the screen and parse

                    # Below block HTTP packet
                    if tcp.srcPort == 80 or tcp.destPort == 80: # Checks port number source and destination
                        print(TAB_2 + 'HTTP Data:')
                        try:
                            http = HTTP(tcp.data) # Create HTTP object according to TCP data
                            httpInfo = str(http.data).split('\n') # Create another object to print data
                            for line in httpInfo:
                                print(DATA_TAB_3 + str(line)) # Print line by line in httpInfo
                        except:
                            print(formatMultiLine(DATA_TAB_3, tcp.data))
                    
                    else: # Other packets that are not HTTP
                        print(TAB_2 + 'TCP Data:')
                        print(formatMultiLine(DATA_TAB_3, tcp.data))

            # Below block prints Other IPv4 packets
            else:
                print(TAB_1 + 'Other IPv4 Data:')
                print(formatMultiLine(DATA_TAB_2, ipv4.data))

        #if protocol number is different from 8
        else:
            print('Ethernet Data:')
            print(formatMultiLine(DATA_TAB_1, eth.data))

    pcap.close() #closes the created .pcap file

    print('\n\n\nTotal number of packet: ' + str(count))

if __name__== "__main__":

    main() #calls the main function
