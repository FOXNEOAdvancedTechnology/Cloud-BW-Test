all: test_send_dgram test_rx_dgram

test_send_dgram: test_send_dgram.c
	gcc -o test_send_dgram test_send_dgram.c

test_rx_dgram: test_rx_dgram.c
	gcc -o test_rx_dgram test_rx_dgram.c

