# s7-parser

S7 protocol parser using Libpcap. You can extract the S7 packets from a PCAP file with both IT and industrial protocols, to study only the S7 packets. 

S7comm (S7 Communication) is a Siemens proprietary protocol that runs between programmable logic controllers (PLCs) of the Siemens S7-300/400 family. 
It is used for PLC programming, exchanging data between PLCs, accessing PLC data from SCADA (supervisory control and data acquisition) systems and diagnostic purposes.

I created this because the S7's Wireshark filter does not recognise *some* packets correctly and the Python library scapy did not load some of the example pcaps correctly.

## Usage

```
./s7parser $input_file $output_file
```

Testing with one of the test PCAP files in *s7_test/* :

```
./s7parser s7_test/password.pcapng result_test.pcap
```

The result is a PCAP with only the S7 extracted packets:

![image](https://i.imgur.com/V48YdlW.jpg)
 

## Installation

```
apt install libpcap-dev
git clone https://github.com/ricardojoserf/s7-parser
cd s7-parser/
gcc s7.c -o s7parser -lpcap
```

## References

- https://www.devdungeon.com/content/using-libpcap-c

- http://yuba.stanford.edu/~casado/pcap/section1.html

- http://yuba.stanford.edu/~casado/pcap/section4.html

- http://gmiru.com/article/s7comm/

- http://gmiru.com/article/s7comm-part2/
