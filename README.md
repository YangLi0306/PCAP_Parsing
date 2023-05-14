# PCAP_Parsing
Simple parsing of PCAP traffic files  

Simple parsing of pcap files using C/C++, parsing the source/destination IP address, source/destination port, transport layer protocol, HTTP, SSL/TLS, DNS protocol, ARP and ICMP for each packet

## Environment
* Ubuntu 18.04
* libpcap
* gcc

## Run
```shell
gcc readpcap.c -o readpcap -lpcap  
```
```shell
./readpcap 
```


