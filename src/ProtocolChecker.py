import os
import json

LAYER_T_TAG = "Transport Layer"
LAYER_S_TAG = "Session Layer"
LAYER_P_TAG = "Presentation layer"
LAYER_A_TAG = "Application layer"

# https://wiki.wireshark.org/InternetProtocolFamily


class ProtocoCheker(object):

    def __init__(self, Dblink, DbType='json'):
        self.scoreDict = None
        if DbType == 'json':
            if os.path.exists(Dblink):
                with open(Dblink) as fh:
                    self.scoreDict = json.loads(fh.read())
        print("Loaded the protocol Json file: ")
        print(self.scoreDict)

    def matchScore(self, compareDict):
        compareDict = {'notEncript': 5, 'Layer WG': 13, 'DATALayer TLS': 3, 'TLSv1 Record Layer: Handshake Protocol: Multiple Handshake Messages': 2,
                       'TLSv1 Record Layer: Change Cipher Spec Protocol: Change Cipher Spec': 2, 'TLSv1 Record Layer: Handshake Protocol: Encrypted Handshake Message': 2, 'TLSv1 Record Layer: Application Data Protocol: ldap': 9}
        confVal = 0
        pckCount = 0
        if not self.scoreDict:
            return 0
        for k, val in compareDict.items():
            tempVal = 0
            pckCount += val
            if 'notEncript' in k:
                tempVal = 0
            else:
                for proK in self.scoreDict[LAYER_A_TAG].keys():
                    if proK in k and self.scoreDict[LAYER_A_TAG][proK] > tempVal:
                        tempVal = self.scoreDict[LAYER_A_TAG][proK]
            confVal += tempVal*val
            print(">>" + str(tempVal))

        return float(confVal)/pckCount


def testCase():
    checker = ProtocoCheker('ProtocalRef.json')
    value = checker.matchScore(None)
    print('value:'+str(value))


if __name__ == '__main__':
    testCase()
