# Packet_Parser [PQC]
**Program Design Purpose**: We want to check/test whether the communication between two points (such as 2 servers) has the resistance ability for Quantum Crypto Attack.

[TOC]

- [Packet_Parser [PQC]](#packet-parser--pqc-)
    + [Introduction](#introduction)
          + [Packet_Parser_PQC Main UI View:](#packet-parser-pqc-main-ui-view-)
    + [Program Design](#program-design)
          + [Packet Collection Module](#packet-collection-module)
          + [Protocol parsing and match module](#protocol-parsing-and-match-module)
          + [Result visualization module](#result-visualization-module)
        * [Program Work Flow](#program-work-flow)
        * [Data Parsing Process](#data-parsing-process)
        * [Protocol QS Score Calculation](#protocol-qs-score-calculation)
      - [Program Setup](#program-setup)
          + [Development Environment : python 3.7.4](#development-environment---python-374)
          + [Additional Lib/Software Need](#additional-lib-software-need)
          + [Hardware Needed : None](#hardware-needed---none)
          + [Program Files List](#program-files-list)
      - [Program Usage](#program-usage)
          + [Program Execution](#program-execution)
          + [Load packets data from file](#load-packets-data-from-file)
          + [Load packet from network interface](#load-packet-from-network-interface)
      - [Problem and Solution](#problem-and-solution)

### Introduction

This project is aimed to develop a probe/scanner program to analysis the network packets between two points to give the confidence level of the resistance ability for Post Quantum Crypto Attack. 

As we don’t have any way to simulate the quantum crypto attack, so what we want is parsing the network packet from the host/destination  side or in the mid to analysis the network communication protocol to identify whether the communication is quantum safe. We will compare the protocol with our data base quantum safe standard to give a value. The standard we want to use is NSA_Suite_B_Cryptography ‘s Quantum resistant suite. For example: 

- If we find the packet is using protocol OpenSSH 2.3.1(SSH2), as its encryption use aes128-ctr, we say it doesn’t have the resistance ability for Quantum Crypto Attack. 


- If we find the packet is using WireGuard protocol, as it is using Curve25519 for key exchange, ChaCha20 for symmetric encryption, Poly1305 for message authentication codes, SipHash for hashtable keys and BLAKE2s for cryptographic hash function, so we are 80% confident about it have the resistance ability for Quantum Crypto Attack. 


###### Packet_Parser_PQC Main UI View: 

![](doc/img/mainUI.png)

`Version: 0.1` 



------

### Program Design

The program contents three main parts: 

·     Network traffic packet collection/sniffing module.

·     Protocol parsing and QS score calculation matching module. 

·     Result visualization UI module.

###### Packet Collection Module

The Network traffic packet collection module will sniff all the communication packet from the cap file or from the network interface. 

###### Protocol parsing and match module

Parsing the protocol detail from the TCP/UDP layer and above. Match the primitives used by the protocol then generate the confidence level of the resistance ability for Quantum Crypto Attack. Our database need to continuous update during our research.

###### Result visualization module

We want to design some UI/Dashboard to show all the communication between A and B in a list , then  categorized all the packets by protocol  types and highlight the result we calculated to give the user a conclusion. 

##### Program Work Flow 

Each module will run in a individual thread, the program work flow diagram is shown below: 

![](doc/img/DesignFlow.png)

##### Data Parsing Process 

In the Data Parsing Module we parse the data with below sequence: 

![](doc/img/dataFlow.png)



##### Protocol QS Score Calculation 

We calculate a protocol's quantum safe score based on the NSA_Suite_B_Cryptography ‘s Quantum resistant suite[https://en.wikipedia.org/wiki/NSA_Suite_B_Cryptography] For example the WireGuard protocol : 

| Standard                                                     | WG Used Algo | Match standard |
| ------------------------------------------------------------ | ------------ | -------------- |
| Advanced Encryption Standard (AES), per FIPS 197, using 256 bit keys to protect up to TOP SECRET | ChaCha20     | Yes            |
| Elliptic Curve Diffie-Hellman (ECDH) Key Exchange, per FIPS SP 800-56A, using Curve P-384 to protect up to TOP SECRET. | Curve25519   | No             |
| Elliptic Curve Digital Signature Algorithm (ECDSA), per FIPS 186-4 | Curve25519   | No             |
| Secure Hash Algorithm (SHA), per FIPS 180-4, using SHA-384 to protect up to TOP SECRET. | BLAKE2s      | Yes            |
| Diffie-Hellman (DH) Key Exchange, per RFC 3526, minimum 3072-bit modulus to protect up to TOP SECRETPoly1305 | Poly1305     | Yes            |
| RSA for key establishment (NIST SP 800-56B rev 1) and digital signatures (FIPS 186-4), minimum 3072-bit modulus to protect up to TOP SECRET | Poly1305     | Yes            |

So we give **WG[QS-Score]** = 6.6667



------

#### Program Setup

###### Development Environment : python 3.7.4

###### Additional Lib/Software Need

1. **wxPython** : https://docs.wxpython.org/index.html

   ```
   Install: pip install wxPython
   ```

2. **pyShark** / **tshark** : https://github.com/KimiNewt/pyshark

   ```
   Install: pip install pyshark
   ```

###### Hardware Needed : None

###### Program Files List 

| Program File           | Execution Env | Description                                        |
| ---------------------- | ------------- | -------------------------------------------------- |
| src/uiRun.py           | python 3      | main UI frame                                      |
| src/uiPanel.py         | python 3      | Result visualization display panel                 |
| src/pkgGlobal.py       | python 3      | Global parameter controller                        |
| src/PacketParser.py    | python 3      | Packet paring module.                              |
| src/ProtocolChecker.py | python 3      | Protocol matching and QS score calculation module. |
| src/DataMgr.py         | python 3      | Program internal data management module.           |
| ProtocolRef.json       |               | QS scores matching dictionary.                     |
| capData/*.cap, *capng  |               | Test packet capture data                           |



------

#### Program Usage

###### Program Execution 

```
python uiRun.py
```

###### Load packets data from file 

1. In the UI, select `Load Data` from the menu bar and select `Load From File`: 

![](doc/img/loadF.png)

2. Select the file and press `open` button, after file loaded press the `parse data` button



###### Load packet from network interface 

1. Run the program under **admin permission**. In the UI, select `Load Data` from the menu bar and select `Load From netowork interface`: 

![](doc/img/loadN.png)

2. Select the network interface you want to sniff.

3. set how long you want to sniff (interface:Wi-Fi:**30** <- this number means sniff packets in 30 sec ), please void set the number too big. As I didn't use the file iterator to cache the packet data into a tmp file, so all the sniffed packet data will be saved in your computer memory. If you are watching a video and use the sniff function, there may be a memory error after running the sniff for a shot while. 

   

------

#### Problem and Solution

Refer to `doc/ProblemAndSolution.md`



------

> Last edit by LiuYuancheng(liu_yuan_cheng@hotmail.com) at 14/01/2022

