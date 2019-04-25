# Send RTP stream with DPDK

Sends an RTP stream with specified inter-packet gap, whose length is measured by x86 Time Stamp Counter (TSC) cycles.

(clock_gettime takes too long to read)

Usage:
```
test_tx_rtp_dpdk -- -m [dst MAC] -s [src IP] -d [dst IP] -g [inter packet gap in TSC cycles] 
```
For example:
```
./build/test_tx_rtp_dpdk -- -m 0f:70:4a:e1:dd:34 -s 192.30.0.73 -d 192.30.0.194 -g 1400
```
As per usual, put DPDK EAL options ahead of `--` if needed.  For example:
```
./build/test_tx_rtp_dpdk -v -- -m 0f:70:4a:e1:dd:34 -s 192.30.0.73 -d 192.30.0.194 -g 1400
```
