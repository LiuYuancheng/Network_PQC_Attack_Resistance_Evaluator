#!/usr/bin/python
#-----------------------------------------------------------------------------
# Name:        DataMgr.py
#
# Purpose:     Data manager module used to control all the other data processing 
#              modules and store the interprocess/result data.
#
# Author:      Yuancheng Liu
#
# Created:     2022/01/16
# Version:     v_0.1
# Copyright:   n.a
# License:     n.a
#-----------------------------------------------------------------------------
import os 
import time
from fnmatch import fnmatch
import threading

import pkgGlobal as gv
import PacketParser as pp
import ProtocolChecker as pc

LOOP_T = 0.5 # Thread loop time interval

#-----------------------------------------------------------------------------
#-----------------------------------------------------------------------------
class DataMgr(object):
    """ Manager onject integrated in to store the data.""" 
    def __init__(self) -> None:
        super().__init__()
        self.parser = pp.PacketParser()
        self.checker = pc.ProtocoCheker(gv.PRO_SCORE_REF)
        self.proList = {}
        self.proSumDict = {}
        self.soreRst = {}

#-----------------------------------------------------------------------------
    def calCommSumDict(self):
        """ Calculate the protocal summery dictionary."""
        self.proSumDict = {}
        for item in self.proList:
            keyVal =  item[gv.SRC_TAG]+'-'+item[gv.DES_TAG]  
            if not (keyVal in self.proSumDict.keys()):
                self.proSumDict[keyVal] = pp.protcolRcdDict(item[gv.SRC_TAG], item[gv.DES_TAG])
            self.proSumDict[keyVal].addRecord(item)

#-----------------------------------------------------------------------------
    def calQSScore(self):
        """ Calculate the current stored data's QS score."""
        self.soreRst = {}
        for key, item in self.proSumDict.items():
            value = self.checker.matchScore(item.encriptDict)
            self.soreRst[key] = value

#-----------------------------------------------------------------------------
    def loadFile(self, filePath):
        """ Load data frome the pcap file.
        Args:
            filePath ([str]): cap file type
        """
        if os.path.exists(filePath) and (fnmatch(filePath, '*.cap') or fnmatch(filePath, '*.pcap')or fnmatch(filePath, '*.pcapng')):
            self.parser.loadCapFile(filePath)
            self.proList = self.parser.getProtocalList()
            return True
        print(">> Error: file not exist or type not valid")
        return False

#-----------------------------------------------------------------------------
    def loadNetLive(self, interfaceName, packetCount = 10):
        self.parser.loadNetLive(interfaceName, packetCount = packetCount)
        self.proList = self.parser.getProtocalList()
        return True

#-----------------------------------------------------------------------------
    def getProtocalDict(self):
        return self.proSumDict

    def getScoreDict(self):
        return self.soreRst

#-----------------------------------------------------------------------------
#-----------------------------------------------------------------------------
class DataMgrPT(threading.Thread):
    """ A Package class used to run the data manager in parallel thread with 
        other thread. (PT for parallel threading)
    """
    def __init__(self, threadID, name, debugMD=False):
        threading.Thread.__init__(self)
        self.dataMgr = DataMgr()
        self.debugMD = debugMD
        self.fileNeedLoad = None
        self.interfaceNeedLoad = None
        self.interfacePacktNum = 30
        self.updateFlag = False
        self.terminate = False
        
    #-----------------------------------------------------------------------------
    def loadFile(self, filePath):
        self.fileNeedLoad = filePath
        self.interfaceNeedLoad = None
        self.updateFlag = True
    
    #-----------------------------------------------------------------------------
    def loadNetLive(self, interfaceName, packetCount):
        self.interfaceNeedLoad = interfaceName
        self.interfacePacktNum = packetCount
        self.fileNeedLoad = False
        self.updateFlag = True
        return True

    #-----------------------------------------------------------------------------
    def run(self):
        while not self.terminate:
            if self.updateFlag:
                if self.debugMD: print(">> Load the data:")
                if self.fileNeedLoad:
                    print("From File %s" %str(self.fileNeedLoad))
                    self.dataMgr.loadFile(self.fileNeedLoad)
                    self.fileNeedLoad = None
                
                if self.interfaceNeedLoad:
                    print('From Network Interface: %s' %str(self.interfaceNeedLoad))
                    self.dataMgr.loadNetLive(self.interfaceNeedLoad, self.interfacePacktNum)
                    self.interfaceNeedLoad = None

                self.dataMgr.calCommSumDict()
                self.dataMgr.calQSScore()
                self.updateFlag = False
            time.sleep(LOOP_T)
        print("DataMangerMT thread stoped!")

    #-----------------------------------------------------------------------------
    def getProtocalDict(self):
        if self.updateFlag: return None
        return self.dataMgr.getProtocalDict()

    def getScoreDict(self):
        if self.updateFlag: return None
        return self.dataMgr.getScoreDict()
    
    def checkUpdating(self):
        return self.updateFlag 

    #-----------------------------------------------------------------------------
    def stop(self):
        """ Stop the thread."""
        self.terminate = True

#-----------------------------------------------------------------------------
#-----------------------------------------------------------------------------
def testCase(mode=0):
    if mode == 0:
        print("> Start test: Init datamanager ")
        dataMgr = DataMgr()
        r1 = dataMgr.loadFile('FILE_NOT_EXIST!')
        r2 = dataMgr.loadFile('capData/test_normal.pcapng')
        result = 'Pass' if (not r1) and r2 else 'Fail'
        print(">> Test load file: %s" %result)

        dataMgr.calCommSumDict()
        print('>> calculate the protocol summery : ')
        print(dataMgr.getProtocalDict())

        dataMgr.calQSScore()
        print('>> calculate the quantum safe score : ')
        print(dataMgr.getScoreDict())
        dataMgr = None 

        print("\n> Test parallel thread data manager.")

        dataMgrMT = DataMgrPT(1, 'Test MultiThread')
        dataMgrMT.start()
        dataMgrMT.loadFile('capData/test_normal.pcapng')

        while dataMgrMT.checkUpdating():
            time.sleep(0.5)
        
        print('>> print the protocol summery : ')
        print(dataMgrMT.getProtocalDict())

        print('>> print the quantum safe score : ')
        print(dataMgrMT.getScoreDict())

        dataMgrMT.stop()
    if mode == 1: 
        print("> Start test: load from Wifi network interface ")
        dataMgrMT = DataMgrPT(1, 'Test MultiThread')
        dataMgrMT.start()
        dataMgrMT.loadNetLive('Wi-Fi', 50)
        while dataMgrMT.checkUpdating():
            time.sleep(0.5)
        
        print('>> print the protocol summery : ')
        print(dataMgrMT.getProtocalDict())

        print('>> print the quantum safe score : ')
        print(dataMgrMT.getScoreDict())
        dataMgrMT.stop()

    else:
        print('>> Put your own test code here:')
        
if __name__ == '__main__':
    testCase()
    #testCase(mode=1)

