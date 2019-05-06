# Test reciever for RTP data using DPDK 

This program recieves RTP data using DPDK.  Right now it does not filter on UDP DST port, but does reject all packets under 200 bytes (LLDP, etc.).  Output is JSON.
```
./build/test_rx_rtp_dpdk
```
