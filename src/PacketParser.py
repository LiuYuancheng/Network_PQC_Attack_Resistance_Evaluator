import pyshark
# https://github.com/KimiNewt/pyshark
# https://wiki.wireshark.org/CaptureSetup/Ethernet
#capture = pyshark.RemoteCapture('192.168.1.101', 'eth0')
# capture = pyshark.FileCapture('wireguard_ping_tcp.pcap')
#capture = pyshark.FileCapture('capData/test_WGVPN.pcap')
capture = pyshark.FileCapture('capData/test_GPVPN.pcapng')
#capture.sniff(timeout=10)

import re

packetInfoList= []



with open('packetdetail.txt', 'a') as fh:
    for cap in capture:
        capMsgs = str(cap)
        lines = capMsgs.split('\n')

        layerList = []
        srcIP, distIP, protocalInfo = '', '', ''
        for line in lines:
            #fh.write(line)
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


        print (str(packetInfo))
    


#print(capture[1])