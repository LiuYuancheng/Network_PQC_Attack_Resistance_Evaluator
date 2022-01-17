#!/usr/bin/python
#-----------------------------------------------------------------------------
# Name:        DataMgr.py
#
# Purpose:     Data manager 
#
# Author:      Yuancheng Liu
#
# Created:     2022/01/16
# Version:     v_0.1
# Copyright:   n.a
# License:     n.a
#-----------------------------------------------------------------------------

import pkgGlobal as gv
import PacketParser as pp
import ProtocolChecker as pc

class DataMgr(object):

    def __init__(self) -> None:
        super().__init__()
        self.parser = pp.PacketParser()
        self.checker = pc.ProtocoCheker(gv.PRO_SCORE_REF)
        self.proList = None

    def loadFile(self, filePath):
        self.parser.loadCapFile(filePath)
        self.proList = self.parser.getProtocalList()

    def getCommSumDict(self):
        proSumDict = {}
        for item in self.proList:
            keyVal =  item[gv.SRC_TAG]+'-'+item[gv.DIS_TAG]  
            if keyVal in proSumDict.keys():
                proSumDict[keyVal].addRecord(item)
            else:
                proSumDict[keyVal] = pp.protcolRcdDict(item[gv.SRC_TAG], item[gv.DIS_TAG])

        return proSumDict
    
    def getCrtScore(self, proSumDict=None):
        soreRst = {}
        for key, item in proSumDict.items():
            value = self.checker.matchScore(item.encriptDict)
            soreRst[key] = value
        return soreRst


def main():
    print(">> Init the packet parser. ")
    dataMgr = DataMgr()
    #parser.loadCapFile('capData/test_GPVPN.pcapng')
    #parser.loadCapFile('capData/test_SSHv1.pcap')
    #parser.loadCapFile('capData/test_WGVPN.pcap')
    dataMgr.loadFile('capData/test_normal.pcapng')
    proSumDict = dataMgr.getCommSumDict()
    print(dataMgr.getCrtScore(proSumDict=proSumDict))

        
if __name__ == '__main__':
    main()