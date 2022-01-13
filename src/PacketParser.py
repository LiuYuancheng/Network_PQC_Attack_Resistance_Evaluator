import pyshark
# https://github.com/KimiNewt/pyshark
#capture = pyshark.RemoteCapture('192.168.1.101', 'eth0')
# capture = pyshark.FileCapture('wireguard_ping_tcp.pcap')
capture = pyshark.FileCapture('SSHv2.cap')
#capture.sniff(timeout=10)

for cap in capture:
    capMsgs = str(cap)
    print(capMsgs)
    print(">>")
    continue
    if 'IP' in cap:
        data = str(cap['IP'])
        lines = data.split('\n')
        for line in lines:
            if ('Protocol') in line: print(line)

    


#print(capture[1])