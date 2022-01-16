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

def main():
    print(">> Init the packet parser. ")
    parser = pp.PacketParser()
    #parser.loadCapFile('capData/test_GPVPN.pcapng')
    #parser.loadCapFile('capData/test_SSHv1.pcap')
    parser.loadCapFile('capData/test_WGVPN.pcap')
    
    proList = parser.getProtocalList()
    proSumDict = {}

    for item in proList:
        keyVal =  item[gv.SRC_TAG]+'-'+item[gv.DIS_TAG]  
        if keyVal in proSumDict.keys():
            proSumDict[keyVal].addRecord(item)
        else:
            proSumDict[keyVal] = pp.protcolRcdDict(item[gv.SRC_TAG], item[gv.DIS_TAG])
    
    print(">> Init the protocal checker: ")
    checker = pc.ProtocoCheker('ProtocalRef.json')
    
    for key, item in proSumDict.items():
        value = checker.matchScore(item.encriptDict)
        print("Connection: " + str(key) + " QS-Confidence lvl: " +str(value))

        
if __name__ == '__main__':
    main()