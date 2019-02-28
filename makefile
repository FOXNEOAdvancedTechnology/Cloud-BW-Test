all: test_tx_dgram test_rx_dgram test_tx_pf test_rx_pf

test_tx_dgram: test_tx_dgram.c
	mkdir -p bin
	gcc -o bin/test_tx_dgram test_tx_dgram.c

test_rx_dgram: test_rx_dgram.c
	mkdir -p bin
	gcc -o bin/test_rx_dgram test_rx_dgram.c

test_tx_pf: test_tx_pf.c
	mkdir -p bin
	gcc -o bin/test_tx_pf test_tx_pf.c

test_rx_pf: test_rx_pf.c
	mkdir -p bin
	gcc -o bin/test_rx_pf test_rx_pf.c

clean:
	rm -f bin/* 
	echo Clean done
