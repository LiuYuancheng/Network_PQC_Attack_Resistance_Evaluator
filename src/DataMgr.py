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

import time
import threading

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
            if not (keyVal in proSumDict.keys()):
                proSumDict[keyVal] = pp.protcolRcdDict(item[gv.SRC_TAG], item[gv.DIS_TAG])
            proSumDict[keyVal].addRecord(item)
        return proSumDict
    
    def getCrtScore(self, proSumDict=None):
        soreRst = {}
        for key, item in proSumDict.items():
            value = self.checker.matchScore(item.encriptDict)
            soreRst[key] = value
        return soreRst


class DataMgrMT(threading.Thread):

    def __init__(self, threadID, name):
        threading.Thread.__init__(self)
        self.parser = pp.PacketParser()
        self.checker = pc.ProtocoCheker(gv.PRO_SCORE_REF)
        self.proList = None
        self.terminate = False
        self.proSumDict = {}
        self.soreRst = {}
        self.updateFlag = False
        self.fileNeedLoad = None 
        
    
    def loadFile(self, filePath):
        self.fileNeedLoad = filePath
        self.updateFlag = True
        
    #-----------------------------------------------------------------------------
    def run(self):
        while not self.terminate:
            print("Thread mark")
            if not self.updateFlag:
                time.sleep(0.5)
            else:
                print(">> Calculate the data.")
                self.parser.loadCapFile(self.fileNeedLoad )
                self.proList = self.parser.getProtocalList()
                # reset the storage dict.
                self.proSumDict = {}
                for item in self.proList:
                    keyVal =  item[gv.SRC_TAG]+'-'+item[gv.DIS_TAG]  
                    if not (keyVal in self.proSumDict.keys()):
                        self.proSumDict[keyVal] = pp.protcolRcdDict(item[gv.SRC_TAG], item[gv.DIS_TAG])
                    self.proSumDict[keyVal].addRecord(item)

                self.soreRst = {}
                for key, item in self.proSumDict.items():
                    value = self.checker.matchScore(item.encriptDict)
                    self.soreRst[key] = value
                
                self.updateFlag = False
        print("DataMangerMT thread stoped!")

    
    #-----------------------------------------------------------------------------
    def getProtocalDict(self):
        if self.updateFlag: return None
        return self.proSumDict

    def getScoreDict(self):
        if self.updateFlag: return None
        return self.soreRst
    
    def checkUpdating(self):
        return self.updateFlag 

    #-----------------------------------------------------------------------------
    def stop(self):
        """ Stop the thread."""
        self.terminate = True


def main():
    print(">> Init the packet parser. ")
    dataMgr = DataMgr()
    #parser.loadCapFile('capData/test_GPVPN.pcapng')
    #parser.loadCapFile('capData/test_SSHv1.pcap')
    #parser.loadCapFile('capData/test_WGVPN.pcap')
    dataMgr.loadFile('capData/test_normal.pcapng')
    proSumDict = dataMgr.getCommSumDict()
    for item in proSumDict.values():
        item.printData()
    print(dataMgr.getCrtScore(proSumDict=proSumDict))

    print(">> test multi thread packet parser. ")

    dataMgrMT = DataMgrMTDataMgr.DataMgrMT()
    dataMgrMT.start()
    dataMgrMT.loadFile('capData/test_normal.pcapng')

    while dataMgrMT.checkUpdating():
        time.sleep(0.5)
    
    print(dataMgrMT.getProtocalDict())
    print(dataMgrMT.getScoreDict())

    dataMgrMT.stop()
        
if __name__ == '__main__':
    main()