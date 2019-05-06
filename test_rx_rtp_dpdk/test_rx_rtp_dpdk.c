// Adapted from: https://github.com/DPDK/dpdk/blob/master/examples/skeleton/basicfwd.c
// by Thomas Edwards, Walt Disney Television

/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2015 Intel Corporation
 */

#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <unistd.h>
#include <locale.h>

#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_cycles.h>
#include <rte_lcore.h>
#include <rte_mbuf.h>

#define RX_RING_SIZE 1024
#define TX_RING_SIZE 0 

#define NUM_MBUFS 8191
#define MBUF_CACHE_SIZE 250
#define BURST_SIZE 32

static const struct rte_eth_conf port_conf_default = {
	.rxmode = {
		.max_rx_pkt_len = ETHER_MAX_LEN,
	},
};

void print_time()
{
        time_t     now;
        struct tm *ts;
        char       buf[80];

        /* Get the current time */
        now = time(NULL);

        /* Format and print the time, "ddd yyyy-mm-dd hh:mm:ss zzz" */
        ts = localtime(&now);
        strftime(buf, sizeof(buf), "\"%Y%m%dT%H%M%S\"", ts);

	printf("{\"time\":%s",buf);
}

static inline int
port_init(uint16_t port, struct rte_mempool *mbuf_pool)
{
	struct rte_eth_conf port_conf = port_conf_default;
	const uint16_t rx_rings = 1, tx_rings = 0;
	uint16_t nb_rxd = RX_RING_SIZE;
	uint16_t nb_txd = TX_RING_SIZE;
	int retval;
	uint16_t q;

	if (!rte_eth_dev_is_valid_port(port))
		return -1;

	/* Configure the Ethernet device. */
	retval = rte_eth_dev_configure(port, rx_rings, tx_rings, &port_conf);
	if (retval != 0)
		return retval;

	retval = rte_eth_dev_adjust_nb_rx_tx_desc(port, &nb_rxd, &nb_txd);
	if (retval != 0)
		return retval;

	/* Allocate and set up 1 RX queue per Ethernet port. */
	for (q = 0; q < rx_rings; q++) {
		retval = rte_eth_rx_queue_setup(port, q, nb_rxd,
				rte_eth_dev_socket_id(port), NULL, mbuf_pool);
		if (retval < 0)
			return retval;
	}

	/* Start the Ethernet port. */
	retval = rte_eth_dev_start(port);
	if (retval < 0)
		return retval;

	/* Display the port MAC address. */
	struct ether_addr addr;
	rte_eth_macaddr_get(port, &addr);
	printf("Port %u MAC: %02" PRIx8 " %02" PRIx8 " %02" PRIx8
			   " %02" PRIx8 " %02" PRIx8 " %02" PRIx8 "\n",
			port,
			addr.addr_bytes[0], addr.addr_bytes[1],
			addr.addr_bytes[2], addr.addr_bytes[3],
			addr.addr_bytes[4], addr.addr_bytes[5]);

	/* Enable RX in promiscuous mode for the Ethernet device. */
	rte_eth_promiscuous_enable(port);

	return 0;
}

// recieve packets
void rx_packets(void)
{
	uint16_t port;
	int i,j;
	int timing_start=0;
	struct timespec time_start,time_end,time_total;
	long total_bytes=0;
	char *this_packet;
	uint this_sn,last_sn=-1; 
	struct rte_eth_stats stats;

	printf("\nCore %u receiving packets. [Ctrl+C to quit]\n",
			rte_lcore_id());

        print_time();
        printf(",\"START\":null}\n");
        fflush(stdout);

	/* Run until the application is quit or killed. */
	for (;;) {
		RTE_ETH_FOREACH_DEV(port) {

			/* Get burst of RX packets, from first port of pair. */
			struct rte_mbuf *bufs[BURST_SIZE];
			const uint16_t nb_rx = rte_eth_rx_burst(port, 0,
					bufs, BURST_SIZE);

			if (unlikely(nb_rx == 0))
				continue;
	
			j+=nb_rx;
			for(i=0;i<nb_rx;++i){
				if(bufs[i]->pkt_len>200)  // ignore LLDP, etc.
				{
					this_packet=rte_pktmbuf_mtod(bufs[i],char *);
					this_sn=((this_packet[44] &0xff) << 8 ) | (this_packet[45] & 0xff);
					if((this_sn-last_sn != 1) && (this_sn-last_sn != -32767) &&(last_sn != -1))
					{
						print_time();
						printf(",\"DROP\":{\"last_sn\":%d,\"this_sn\":%d}}\n",last_sn,this_sn);
						fflush(stdout);	
					}	
					if((this_packet[43] & 0xff) == 0xe0){
						print_time();
						printf(",\"MARK\":null}\n");
						fflush(stdout);
					}
				last_sn=this_sn;	
				rte_pktmbuf_free(bufs[i]);
				}

			}
		}
	}
}

int main(int argc, char *argv[])
{
	struct rte_mempool *mbuf_pool;
	unsigned nb_ports;
	uint16_t portid;
	int c;

	/* Initialize the Environment Abstraction Layer (EAL). */
	int ret = rte_eal_init(argc, argv);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Error with EAL initialization\n");

	argc -= ret;
	argv += ret;

	nb_ports = rte_eth_dev_count_avail();
	printf("rte_eth_dev_count_avail()=%d\n",nb_ports);

	/* Creates a new mempool in memory to hold the mbufs. */
	mbuf_pool = rte_pktmbuf_pool_create("MBUF_POOL", NUM_MBUFS * nb_ports,
		MBUF_CACHE_SIZE, 0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());

	if (mbuf_pool == NULL)
		rte_exit(EXIT_FAILURE, "Cannot create mbuf pool\n");

	/* Initialize all ports. */
	RTE_ETH_FOREACH_DEV(portid)
		if (port_init(portid, mbuf_pool) != 0)
			rte_exit(EXIT_FAILURE, "Cannot init port %"PRIu16 "\n",
					portid);

	rx_packets();

	return 0;
}
