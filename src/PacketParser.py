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

SRC_TAG = 'Src'
DIS_TAG = 'Dist'
PRO_TAG = 'Prot'
LAY_TAG = 'Layer'
NTE_TAG = 'notEncript'

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
                SRC_TAG: srcIP,
                DIS_TAG: distIP, 
                PRO_TAG: protocalInfo,
                LAY_TAG: layerList,
            }
            #print(packetInfo)
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
class protcolRctDict(object):

    def __init__(self, src, dist):
        self.src = src
        self.dist = dist
        self.pktCount = 0
        self.tcpCount = 0
        self.udpCount = 0
        self.encriptDict = {NTE_TAG:0}

    def addRecord(self, dataDict):
        self.pktCount +=1
        if 'UDP' in dataDict[PRO_TAG]: self.udpCount +=1
        if 'TDP' in dataDict[PRO_TAG]: self.tcpCount +=1
        if len(dataDict[LAY_TAG]) < 4:
            self.encriptDict[NTE_TAG] +=1
        else:
            for element in dataDict[LAY_TAG][3:]:
                if element in self.encriptDict.keys():
                    self.encriptDict[element] += 1
                else:
                    self.encriptDict[element] = 1

    def printData(self):
        print("src: %s" %str(self.src))
        print("dist: %s" %str(self.dist))
        print("pktCount: %s" %str(self.pktCount))
        print("tcpCount: %s" %str(self.tcpCount))
        print("udpCount: %s" %str(self.udpCount))
        print("encriptDict: %s" %str(self.encriptDict))


#-----------------------------------------------------------------------------
#-----------------------------------------------------------------------------
def main():
    parser = PacketParser()
    #parser.loadCapFile('capData/test_GPVPN.pcapng')
    parser.loadCapFile('capData/test_SSHv1.pcap')
    
    proList = parser.getProtocalList()
    proSumDict = {}

    for item in proList:
        keyVal =   item[SRC_TAG]+'-'+item[DIS_TAG]  
        if keyVal in proSumDict.keys():
            proSumDict[keyVal].addRecord(item)
        else:
            proSumDict[keyVal] = protcolRctDict(item[SRC_TAG], item[DIS_TAG])
    
    #print(proSumDict)
    for item in proSumDict.values():
        item.printData()
    #parser.exportInfo('packetExample/wgInfo.txt')

#-----------------------------------------------------------------------------
if __name__ == '__main__':
    main()

