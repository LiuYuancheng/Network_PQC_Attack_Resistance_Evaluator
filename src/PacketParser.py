#!/usr/bin/python
#-----------------------------------------------------------------------------
# Name:        PacketParser.py
#
# Purpose:     This module will load the network packet file and parsing the related 
#              information from the packet data.
#
# Author:      Yuancheng Liu
#
# Created:     2022/01/13
# Version:     v_0.1
# Copyright:   n.a
# License:     n.a
#-----------------------------------------------------------------------------



import os
import re
import pyshark

# https://github.com/KimiNewt/pyshark
# https://wiki.wireshark.org/CaptureSetup/Ethernet
#capture = pyshark.RemoteCapture('192.168.1.101', 'eth0')
# capture = pyshark.FileCapture('wireguard_ping_tcp.pcap')
#capture = pyshark.FileCapture('capData/test_WGVPN.pcap')
#capture = pyshark.FileCapture('capData/test_GPVPN.pcapng')
#capture.sniff(timeout=10)

#-----------------------------------------------------------------------------
#-----------------------------------------------------------------------------
class PacketParser(object):

    def __init__(self):
        #self.layerList = []
        self.packetInfoLines = None
        self.capture = None

    #-----------------------------------------------------------------------------
    def loadCapFile(self, filePath):
        if not os.path.exists(filePath):
            print(">> file not found")
            return None
        self.packetInfoLines = []
        capture = pyshark.FileCapture(filePath)
        for cap in capture:
            capMsgs = str(cap)
            self.packetInfoLines.append(capMsgs.split('\n'))

    #-----------------------------------------------------------------------------
    def getProtocalList(self):
        if (not self.packetInfoLines) or len(self.packetInfoLines) == 0: return None
        protocalList = []
        for packetInfo in self.packetInfoLines:
            layerList = []
            srcIP, distIP, protocalInfo = '', '', ''
            for line in packetInfo:
                line = line.strip()
                #result = re.search('Layer(.*):', line)
                if len(line) > 0 and line[0] !='\t' and 'Layer' in line:
                    if line[-1] == ':': line = line[:-1]
                    layerList.append(line)
                if 'Protocol:' in line: protocalInfo = str(line.split(':')[1]).lstrip()
                if 'Source:' in line: srcIP = str(line.split(':')[1]).lstrip()
                if 'Destination:' in line: distIP = str(line.split(':')[1]).lstrip()
            packetInfo = {
            'Src': srcIP,
            'Dist': distIP, 
            'Prot': protocalInfo,
            'Layer': layerList,
            }
            print(packetInfo)
            protocalList.append(packetInfo)

        return protocalList

    #-----------------------------------------------------------------------------
    def exportInfo(self, filePath):
        with open(filePath, 'w') as fh:
            for packetInfo in self.packetInfoLines:
                for line in packetInfo:
                    fh.write(line)


#-----------------------------------------------------------------------------
#-----------------------------------------------------------------------------
def main():
    parser = PacketParser()
    parser.loadCapFile('capData/test_WGVPN.pcap')
    proList = parser.getProtocalList()
    for item in proList:
        print(item)

    parser.exportInfo('packetExample/wgInfo.txt')


#-----------------------------------------------------------------------------
if __name__ == '__main__':
    main()

