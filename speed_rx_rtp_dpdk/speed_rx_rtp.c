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

int npackets=0,nignore=-1;

static const struct rte_eth_conf port_conf_default = {
	.rxmode = {
		.max_rx_pkt_len = ETHER_MAX_LEN,
	},
};

struct timespec diff(struct timespec start, struct timespec end)
{
	struct timespec temp;
	if ((end.tv_nsec-start.tv_nsec)<0) {
		temp.tv_sec = end.tv_sec-start.tv_sec-1;
		temp.tv_nsec = 1000000000+end.tv_nsec-start.tv_nsec;
	} else {
		temp.tv_sec = end.tv_sec-start.tv_sec;
		temp.tv_nsec = end.tv_nsec-start.tv_nsec;
	}
	return temp;
}

double tsFloat(struct timespec time)
{
    return ((double) time.tv_sec + (time.tv_nsec / 1000000000.0)) ;
}

extern char *strcomma(double value){
    static char result[64];
    char *result_p = result;
    char separator = ',';
    size_t tail;

    snprintf(result, sizeof(result), "%.2f", value);

    while(*result_p != 0 && *result_p != '.')
        result_p++;

    tail = result + sizeof(result) - result_p;

    while(result_p - result > 3){
        result_p -= 3;
        memmove(result_p + 1, result_p, tail);
        *result_p = separator;
        tail += 4;
    }

    return result;
}
/*
 * Initializes a given port using global settings and with the RX buffers
 * coming from the mbuf_pool passed as a parameter.
 */
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

	/* Run until the application is quit or killed. */
	for (j=0;j<npackets+nignore-1;) {
		/*
		 * Receive packets on a port and forward them on the paired
		 * port. The mapping is 0 -> 1, 1 -> 0, 2 -> 3, 3 -> 2, etc.
		 */
		RTE_ETH_FOREACH_DEV(port) {

			/* Get burst of RX packets, from first port of pair. */
			struct rte_mbuf *bufs[BURST_SIZE];
			const uint16_t nb_rx = rte_eth_rx_burst(port, 0,
					bufs, BURST_SIZE);

			if (unlikely(nb_rx == 0))
				continue;
	
			j+=nb_rx;
			if((j>=nignore) && (timing_start==0)){
				timing_start=1;
				clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &time_start);			
			}
			for(i=0;i<nb_rx;++i){
				if(bufs[i]->pkt_len>200)  // ignore LLDP, etc.
					{
					this_packet=rte_pktmbuf_mtod(bufs[i],char *);
					this_sn=((this_packet[44] &0xff) << 8 ) | (this_packet[45] & 0xff);
					if((this_sn-last_sn != 1) && (this_sn-last_sn != -32767) &&(last_sn != -1))
					{
						printf("DROP,%d,%d\n",last_sn,this_sn);
						fflush(stdout);	
					}	
					if((this_packet[43] & 0xff) == 0xe0){
						printf("MARK\n");
						fflush(stdout);
					}
					last_sn=this_sn;	
					if(timing_start==1)
						total_bytes+=bufs[i]->pkt_len;
					}
				rte_pktmbuf_free(bufs[i]);
			}

		}
	}

	clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &time_end);
	time_total=diff(time_start,time_end);
	printf("time for %d packets, %ld bytes = %f sec\n",npackets,total_bytes,tsFloat(time_total));
	long bitrate=(long)(total_bytes*8.0/tsFloat(time_total));	
	printf("%s bits/s\n",strcomma(bitrate));	

	rte_eth_stats_get(0, &stats);
	printf("stats:\n");
	printf("ipackets: %" PRIu64 "\n", stats.ipackets);
	printf("ibytes: %" PRIu64 "\n", stats.ibytes);
	printf("imissed: %" PRIu64 "\n", stats.imissed);
	printf("ierrors: %" PRIu64 "\n", stats.ierrors);
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

	while ((c = getopt(argc,argv,"n:i:")) != -1)
		switch(c) {
		case 'n':
			npackets=strtol(optarg,NULL,10);
		break;
		case 'i':
			nignore=strtol(optarg,NULL,10);
		break;
		}

	if(npackets<1)
		npackets=100;

	if(nignore<0)
		nignore=100;

	printf("Speed Test based on receive of %d packets after %d initial packets are ignored\n",
		npackets,nignore);
	
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
