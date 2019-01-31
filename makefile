all: test_tx_dgram test_rx_dgram

test_tx_dgram: test_tx_dgram.c
	gcc -o bin/test_tx_dgram test_tx_dgram.c

test_rx_dgram: test_rx_dgram.c
	gcc -o bin/test_rx_dgram test_rx_dgram.c

