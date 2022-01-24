#!/usr/bin/python
#-----------------------------------------------------------------------------
# Name:        PacketParser.py
#
# Purpose:     This module is used to load the network packet file (*.cap, *.pcap,
#               *.pcapng) and parse all the related network layer information from
#               the packet file.
#
# Author:      Yuancheng Liu
#
# Created:     2022/01/13
# Version:     v_0.1
# Copyright:   n.a
# License:     n.a
#-----------------------------------------------------------------------------

import os
import psutil
import pyshark  # https://github.com/KimiNewt/pyshark
import pkgGlobal as gv

#WIFI_DEV = "\\Device\\NPF_{172B21B5-878D-41B5-9C51-FE1DD27C469B}" # windows wifi dev

#-----------------------------------------------------------------------------
#-----------------------------------------------------------------------------

class PacketParser(object):
    """ Parse the packet capture file and convert to layer data."""

    def __init__(self, debugFlg=False):
        self.packetInfoLines = None
        self.debugMD = debugFlg

    #-----------------------------------------------------------------------------
    def loadCapFile(self, filePath):
        """ Load the network packet capture file (*.cap, *.pcap, *.pcapng)
            Args:
                filePath ([str]): pcap file path.
        """
        if os.path.exists(filePath):
            capture = pyshark.FileCapture(filePath)
            self.packetInfoLines = [str(cap).split('\n') for cap in capture]
            if self.debugMD: print(str(self.packetInfoLines))
            return True
        print(">> Error: loadCapFile() file %s not found." % str(filePath))
        return False

    #-----------------------------------------------------------------------------
    def loadNetLive(self, interfaceName, packetCount = 10):
        """ Load the network packet from the network interface.
        """
        addrs = psutil.net_if_addrs()
        if interfaceName in addrs.keys() and interfaceName in gv.gInterfaceDict.keys():
            capture = pyshark.LiveCapture(interface = gv.gInterfaceDict[interfaceName])
            self.packetInfoLines = []
            for captureArr in capture.sniff_continuously(packet_count=packetCount):
                if self.debugMD: print("Captured live packets.")
                self.packetInfoLines += [str(cap).split('\n') for cap in captureArr]  
            print("Finished capture.")
            return True
        else:
            print(">> Error: The network interface  %s not found." % str(interfaceName))
            return False

    #-----------------------------------------------------------------------------
    def getProtocalList(self):
        """ Return a list of the network protocal info dict. 
            Protocol dict example: 
                {'Src': '192.168.2.1', 'Dist': '192.168.2.133', 'Prot': 'TCP (6)', 
                'Layer': ['Layer ETH', 'Layer IP', 'Layer TCP', 'Layer SSH']}
        """
        if (not self.packetInfoLines) or len(self.packetInfoLines) == 0:
            if self.debugMD: print("No packet data stored.")
            return None
        protocalList = []
        for packetInfo in self.packetInfoLines:
            layerList = []
            srcIP, distIP, protocalInfo = '', '', ''
            for line in packetInfo:
                line = line.strip()
                if len(line) > 0 and line[0] != '\t' and 'Layer' in line:
                    if line[-1] == ':': line = line[:-1]
                    layerList.append(line)
                if 'Protocol:' in line: protocalInfo = str(line.split(':')[1]).lstrip()
                if 'Source:' in line: srcIP = str(line.split(':')[1]).lstrip()
                if 'Destination:' in line: distIP = str(line.split(':')[1]).lstrip()
            packetInfo = {
                gv.SRC_TAG: srcIP,
                gv.DES_TAG: distIP,
                gv.PRO_TAG: protocalInfo,
                gv.LAY_TAG: layerList,
            }
            if self.debugMD: print(packetInfo)
            protocalList.append(packetInfo)
        return protocalList

    #-----------------------------------------------------------------------------
    def exportInfo(self, filePath):
        """ Write the full packet information in a file.
            Args:
                filePath ([str]): file name or file path.
        """
        with open(filePath, 'w') as fh:
            for packetInfo in self.packetInfoLines:
                for line in packetInfo:
                    fh.write(line)

#-----------------------------------------------------------------------------
#-----------------------------------------------------------------------------
class protcolRcdDict(object):
    """ A data type class used to record all the protocol types between 2 IP 
        addresses. 
    """
    def __init__(self, src, dist):
        self.src = src
        self.dist = dist
        self.pktCount = 0
        self.tcpCount = 0
        self.udpCount = 0
        self.encriptDict = {gv.NTE_TAG: 0} # encryption layer record dict.

    #-----------------------------------------------------------------------------
    def addRecord(self, dataDict):
        """ Add a new packet info in the encryption record dict. 
            Args:
                dataDict ([dict]): example:
                {'Src': '192.168.2.1', 'Dist': '192.168.2.133', 'Prot': 'TCP (6)', 
                'Layer': ['Layer ETH', 'Layer IP', 'Layer TCP', 'Layer SSH']}
        """
        self.pktCount +=1
        if 'UDP' in dataDict[gv.PRO_TAG]: self.udpCount +=1
        if 'TCP' in dataDict[gv.PRO_TAG]: self.tcpCount +=1
        if len(dataDict[gv.LAY_TAG]) < 4:
            self.encriptDict[gv.NTE_TAG] +=1
        else:
            for element in dataDict[gv.LAY_TAG][3:]:
                if element in self.encriptDict.keys():
                    self.encriptDict[element] += 1
                else:
                    self.encriptDict[element] = 1

    #-----------------------------------------------------------------------------
    def printData(self):
        print("src: %s" %str(self.src))
        print("dist: %s" %str(self.dist))
        print("pktCount: %s" %str(self.pktCount))
        print("tcpCount: %s" %str(self.tcpCount))
        print("udpCount: %s" %str(self.udpCount))
        print("encriptDict: %s" %str(self.encriptDict))

    #-----------------------------------------------------------------------------
    def getSourceIPaddr(self):
        return self.src

    def getDistIPaddr(self):
        return self.dist

    def getTotolPktNum(self):
        return self.pktCount

    def getTcpPktNum(self):
        return self.tcpCount
    
    def getUdpPktNum(self):
        return self.udpCount

    def getEncriptDict(self):
        return self.encriptDict

#-----------------------------------------------------------------------------
#-----------------------------------------------------------------------------
def testCase(mode=0):
    if mode == 0:
        parser = PacketParser(debugFlg=True)
        #parser.loadCapFile('capData/test_GPVPN.pcapng')
        #parser.loadCapFile('capData/test_normal.pcapng')
        #parser.loadCapFile('capData/test_SSHv1.pcap')
        #parser.loadCapFile('capData/test_SSHv2.cap')
        parser.loadCapFile('capData/test_WGVPN.pcap')
        proList = parser.getProtocalList()
        proSumDict = {}

        for item in proList:
            keyVal = item[gv.SRC_TAG]+'-'+item[gv.DES_TAG]
            if not (keyVal in proSumDict.keys()):
                proSumDict[keyVal] = protcolRcdDict(item[gv.SRC_TAG], item[gv.DES_TAG])
            proSumDict[keyVal].addRecord(item)
        #print(proSumDict)
        for item in proSumDict.values():
            item.printData()
        parser.exportInfo('packetExample/wgInfo.txt')
    elif mode == 1:
        parser = PacketParser(debugFlg=True)
        parser.loadNetLive('Wi-Fi')
        proList = parser.getProtocalList()
        proSumDict = {}

        for item in proList:
            keyVal = item[gv.SRC_TAG]+'-'+item[gv.DES_TAG]
            if not (keyVal in proSumDict.keys()):
                proSumDict[keyVal] = protcolRcdDict(item[gv.SRC_TAG], item[gv.DES_TAG])
            proSumDict[keyVal].addRecord(item)
        #print(proSumDict)
        for item in proSumDict.values():
            item.printData()
        parser.exportInfo('packetExample/wifiInfo.txt')
    else:
        print("Put your own test code here:")


#-----------------------------------------------------------------------------
if __name__ == '__main__':
    testCase()
    #testCase(mode=1)

