# Http(s) Request Logger

This module is used to log all the outgoing http(s) request send out from a Ubuntu machine to collect data to analyze whether there is any malicious activities generated from the host. The data will be record in the `Logs`fodler. This project includes 5 module as shown below. All the module need to be run under `sudo` permission. 

#### httpRequestLogger.py

One local HTTP/HTTPS Traffic Monitor using pyshark (tshark) : Captures outbound HTTP/HTTPS traffic from a network interface logs all the requests to log files. It will only capture the success sent out request. The function included: 

- HTTP (port 80) traffic is fully decoded: method, host, URI, headers.
- HTTPS (port 443) traffic shows IP/port metadata only (TLS is encrypted).
- For full HTTPS decryption you would need the server's private key or use SSLKEYLOGFILE with a supporting application (see --keylog option).

Requirements Lib:

```
sudo apt install tshark
sudo pip3 install pyshark --break-system-packages
```

