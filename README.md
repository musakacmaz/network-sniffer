# network-sniffer
A network sniffer that can intercept and log traffic passing over a digital network or part of a network written in python3.

## Prerequisites

You need to run this program on a Linux operating system.

## Setup and Run

Get the code by either cloning this repository using git then change the directory.

```
cd network-sniffer
```

Compile and run the program by using command below.

```
sudo python3 sniffer.py face 5
```

“face” is the output .pcap file. User doesn’t need to write .pcap extension. “5” is the desired time in seconds.

The program saves the captured packets into a pcap file automatically. You can open the output pcap file by [Wireshark](https://www.wireshark.org).
