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
        keyVal =  item[pp.SRC_TAG]+'-'+item[pp.DIS_TAG]  
        if keyVal in proSumDict.keys():
            proSumDict[keyVal].addRecord(item)
        else:
            proSumDict[keyVal] = pp.protcolRctDict(item[pp.SRC_TAG], item[pp.DIS_TAG])
    
    print(">> Init the protocal checker: ")
    checker = pc.ProtocoCheker('ProtocalRef.json')
    
    for key, item in proSumDict.items():
        value = checker.matchScore(item.encriptDict)
        print("Connection: " + str(key) + " QS-Confidence lvl: " +str(value))

        
if __name__ == '__main__':
    main()