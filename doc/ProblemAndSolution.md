# **Problem and Solution**

**In this document we will share the valuable problems and the solution we meet during the project development as a reference menu for the new programmer who may take over this project for further development. Later we will sort the problem based on the problem <type>.**

[TOC]

**Format:** 

**Problem**: (Situation description)

**OS Platform** :

**Error Message**:

**Type**: Setup exception

**Solution**:

**Related Reference**:

------

###### Problem[1]: Share the android phone screen to PC for online demo with MS-Teams. 

**OS Platform** : Windows 

**Error Message**: 

```
PS C:\Works\NCSCyber\Packet__Parser_PQC\src> & C:/Users/liu_y/AppData/Local/Programs/Python/Python37-32/python.exe c:/Works/NCSCyber/Packet__Parser_PQC/src/PacketParser.py
Traceback (most recent call last):
  File "c:/Works/NCSCyber/Packet__Parser_PQC/src/PacketParser.py", line 4, in <module>
    capture.sniff(timeout=10)
  File "C:\Users\liu_y\AppData\Local\Programs\Python\Python37-32\lib\site-packages\pyshark\capture\capture.py", line 137, in load_packets
    self.apply_on_packets(keep_packet, timeout=timeout, packet_count=packet_count)
  File "C:\Users\liu_y\AppData\Local\Programs\Python\Python37-32\lib\site-packages\pyshark\capture\capture.py", line 274, in apply_on_packets
    return self.eventloop.run_until_complete(coro)
  File "C:\Users\liu_y\AppData\Local\Programs\Python\Python37-32\lib\asyncio\base_events.py", line 587, in run_until_complete
    return future.result()
  File "C:\Users\liu_y\AppData\Local\Programs\Python\Python37-32\lib\asyncio\tasks.py", line 442, in wait_for
    return fut.result()
  File "C:\Users\liu_y\AppData\Local\Programs\Python\Python37-32\lib\site-packages\pyshark\capture\capture.py", line 283, in packets_from_tshark
    tshark_process = await self._get_tshark_process(packet_count=packet_count)
  File "C:\Users\liu_y\AppData\Local\Programs\Python\Python37-32\lib\site-packages\pyshark\capture\live_capture.py", line 87, in _get_tshark_process
    dumpcap_params = [get_process_path(process_name="dumpcap", tshark_path=self.tshark_path)] + self._get_dumpcap_parameters()
  File "C:\Users\liu_y\AppData\Local\Programs\Python\Python37-32\lib\site-packages\pyshark\tshark\tshark.py", line 60, in get_process_path
    self.apply_on_packets(keep_packet, timeout=timeout, packet_count=packet_count)
  File "C:\Users\liu_y\AppData\Local\Programs\Python\Python37-32\lib\site-packages\pyshark\capture\capture.py", line 274, in apply_on_packets    return self.eventloop.run_until_complete(coro)
  File "C:\Users\liu_y\AppData\Local\Programs\Python\Python37-32\lib\asyncio\base_events.py", line 587, in run_until_complete
    return future.result()
  File "C:\Users\liu_y\AppData\Local\Programs\Python\Python37-32\lib\asyncio\tasks.py", line 442, in wait_for
    return fut.result()
  File "C:\Users\liu_y\AppData\Local\Programs\Python\Python37-32\lib\site-packages\pyshark\capture\capture.py", line 283, in packets_from_tshark
    tshark_process = await self._get_tshark_process(packet_count=packet_count)
  File "C:\Users\liu_y\AppData\Local\Programs\Python\Python37-32\lib\site-packages\pyshark\capture\live_capture.py", line 87, in _get_tshark_process
    dumpcap_params = [get_process_path(process_name="dumpcap", tshark_path=self.tshark_path)] + self._get_dumpcap_parameters()
  File "C:\Users\liu_y\AppData\Local\Programs\Python\Python37-32\lib\site-packages\pyshark\tshark\tshark.py", line 61, in get_process_path
    "Searched these paths: {}".format(possible_paths)
pyshark.tshark.tshark.TSharkNotFoundException: TShark not found. Try adding its location to the configuration file. Searched these paths: ['C:\\Program Files\\Wireshark\\dumpcap.exe', 'C:\\Program Files\\Wireshark\\dumpcap.exe', 'C:\\Program Files\\Wireshark\\dumpcap.exe']
```



**Type**: Software setup.

**Solution**: 

1. The problem is because wireshare is not install in the C drive 

2. Open the file `Python\Python37-32\Lib\site-packages\pyshark\tshark`

3. Do the change: 

   ![](img/tshark.png)

4. 

**Related Reference**:

https://blog.csdn.net/Dawn510/article/details/92799714

------

