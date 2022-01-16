#!/usr/bin/python
#-----------------------------------------------------------------------------
# Name:        ProtocolChecker.py
#
# Purpose:     This module is used to check all the protocal packets above network
#              Layer 3 and match with the Quantum safe score database to give the 
#              final confidence level of resistence ability for the quantum cyber 
#              attack. 
#
# Author:      Yuancheng Liu
#
# Created:     2022/01/15
# Version:     v_0.1
# Copyright:   n.a
# License:     n.a
#-----------------------------------------------------------------------------

import os
import json
import pkgGlobal as gv

# https://wiki.wireshark.org/InternetProtocolFamily


#-----------------------------------------------------------------------------
#-----------------------------------------------------------------------------
class ProtocoCheker(object):
    """ Count all the protocal packets and match with the Quantum safe score 
        database to give the final confidence level of resistence ability for 
        the quantum cyber attack. 
    """
    def __init__(self, Dblink, DbType='json', debugFlag=False):
        self.scoreDict = None
        if DbType == 'json' and os.path.exists(Dblink):
            with open(Dblink) as fh:
                self.scoreDict = json.loads(fh.read())
        else:
            print("Init Error: Can not find the QS-score json file.")
        self.debugMD = debugFlag
        if self.debugMD:
            print("Loaded the protocol Json file: ")
            print(self.scoreDict)

    #-----------------------------------------------------------------------------
    def matchScore(self, compareDict):
        """ Match the compare protocol dict with the QS-score database and get in 
            final value.

        Args:
            compareDict ([dict]): example data:
            compareDict = { 'notEncript': 5,
                            'Layer WG': 13, 
                            'DATALayer TLS': 3, 
                            'TLSv1 Record Layer: Handshake Protocol: Multiple Handshake Messages': 2,
                            'TLSv1 Record Layer: Change Cipher Spec Protocol: Change Cipher Spec': 2, 
                            'TLSv1 Record Layer: Handshake Protocol: Encrypted Handshake Message': 2, 
                            'TLSv1 Record Layer: Application Data Protocol: ldap': 9}
        Returns:
            [float]: final confidence level of resistence ability for  the quantum 
            cyber attack. 
        """
        confVal = 0
        pckCount = 0
        if not self.scoreDict: return 0
        for cKey, val in compareDict.items():
            tempVal = 0
            pckCount += val
            if gv.NTE_TAG in cKey:
                tempVal = 0
            else:
                for proK in self.scoreDict[gv.LAYER_A_TAG].keys():
                    # find the highest score: for example if it is 'TLSv1.3' it will match with
                    # 'TLS' get 5.0 then match with 'TLSv1.3' get 7.0, then the final reuslt is 7.0.
                    if (proK in cKey) and (self.scoreDict[gv.LAYER_A_TAG][proK] > tempVal):
                        tempVal = self.scoreDict[gv.LAYER_A_TAG][proK]

            confVal += tempVal*val
            #print(">>" + str(tempVal))
            finalScore = float(confVal)/pckCount if pckCount !=0 else confVal
        return finalScore

#-----------------------------------------------------------------------------
#-----------------------------------------------------------------------------
def testCase():
    checker = ProtocoCheker('ProtocalRef.json')
    testCompareDict = { 'notEncript': 5,
                            'Layer WG': 13, 
                            'DATALayer TLS': 3, 
                            'TLSv1 Record Layer: Handshake Protocol: Multiple Handshake Messages': 2,
                            'TLSv1 Record Layer: Change Cipher Spec Protocol: Change Cipher Spec': 2, 
                            'TLSv1 Record Layer: Handshake Protocol: Encrypted Handshake Message': 2, 
                            'TLSv1 Record Layer: Application Data Protocol: ldap': 9}
    value = checker.matchScore(testCompareDict)
    print('value:'+str(value))

if __name__ == '__main__':
    testCase()
