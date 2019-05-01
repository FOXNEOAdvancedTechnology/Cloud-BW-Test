// Adapted from: https://github.com/DPDK/dpdk/blob/master/examples/skeleton/basicfwd.c
// with additonal code from https://github.com/DPDK/dpdk/blob/master/app/test-pmd/txonly.c
/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2015 Intel Corporation
 */

// by Thomas Edwards, Fox Networks Engineering & Operations (Disney)

#include <stdio.h>
#include <stdint.h>
#include <inttypes.h>
#include <unistd.h>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_cycles.h>
#include <rte_lcore.h>
#include <rte_mbuf.h>
#include <rte_udp.h>
#include <rte_ip.h>
#include <rte_byteorder.h>
#include <rte_common.h>
#include <rte_ether.h>
#include <time.h>

#define RX_RING_SIZE 1024
#define TX_RING_SIZE 8192 

#define NUM_MBUFS 8191
#define MBUF_CACHE_SIZE 250
#define BURST_SIZE 32

#define UDP_SRC_PORT 6666 
#define UDP_DST_PORT 6666 

uint64_t DST_MAC=0;
uint32_t IP_SRC_ADDR=0,IP_DST_ADDR=0;
int IPG=0;

#define IP_DEFTTL  64   /* from RFC 1340. */
#define IP_VERSION 0x40
#define IP_HDRLEN  0x05 /* default IP header length == five 32-bits words. */
#define IP_VHL_DEF (IP_VERSION | IP_HDRLEN)

#define TX_PACKET_LENGTH 862
/*
 *  * Work-around of a compilation error with ICC on invocations of the
 *   * rte_be_to_cpu_16() function.
 *    */
#ifdef __GCC__
#define RTE_BE_TO_CPU_16(be_16_v)  rte_be_to_cpu_16((be_16_v))
#define RTE_CPU_TO_BE_16(cpu_16_v) rte_cpu_to_be_16((cpu_16_v))
#else
#if RTE_BYTE_ORDER == RTE_BIG_ENDIAN
#define RTE_BE_TO_CPU_16(be_16_v)  (be_16_v)
#define RTE_CPU_TO_BE_16(cpu_16_v) (cpu_16_v)
#else
#define RTE_BE_TO_CPU_16(be_16_v) \
	(uint16_t) ((((be_16_v) & 0xFF) << 8) | ((be_16_v) >> 8))
#define RTE_CPU_TO_BE_16(cpu_16_v) \
	(uint16_t) ((((cpu_16_v) & 0xFF) << 8) | ((cpu_16_v) >> 8))
#endif
#endif /* __GCC__ */

static const struct rte_eth_conf port_conf_default = {
	.rxmode = {
		.max_rx_pkt_len = ETHER_MAX_LEN,
	},
};

static struct ipv4_hdr  pkt_ip_hdr;  /**< IP header of transmitted packets. */
static struct udp_hdr pkt_udp_hdr; /**< UDP header of transmitted packets. */

struct ether_addr my_addr;

int sn=0; // RTP sequence number
time_t dontmark=0; // keeps Mark to single packet

// convert six colon separated hex bytes string to uint64_t Ethernet MAC address
uint64_t string_to_mac(char *s) {
    unsigned char a[6];
    int rc = sscanf(s, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
                    a + 0, a + 1, a + 2, a + 3, a + 4, a + 5);
    if(rc !=6 ){
	fprintf(stderr, "bad MAC address format. Use like: -m 0a:38:ca:f6:f3:20\n");
	exit(1);
    }
	
    return
        (uint64_t)(a[0]) << 40 |
        (uint64_t)(a[1]) << 32 |
        (uint64_t)(a[2]) << 24 |
        (uint64_t)(a[3]) << 16 |
        (uint64_t)(a[4]) << 8 |
        (uint64_t)(a[5]);
}

// convert a quad-dot IP string to uint32_t IP address
uint32_t string_to_ip(char *s) {
	unsigned char a[4];
	int rc = sscanf(s, "%d.%d.%d.%d",a+0,a+1,a+2,a+3);	
	if(rc != 4){
        	fprintf(stderr, "bad source IP address format. Use like: -s 198.19.111.179\n");
        	exit(1);
	}
	
	return
		(uint32_t)(a[0]) << 24 |
		(uint32_t)(a[1]) << 16 |
		(uint32_t)(a[2]) << 8 |
		(uint32_t)(a[3]);

}

static void
copy_buf_to_pkt_segs(void* buf, unsigned len, struct rte_mbuf *pkt,
		     unsigned offset)
{
	struct rte_mbuf *seg;
	void *seg_buf;
	unsigned copy_len;

	seg = pkt;
	while (offset >= seg->data_len) {
		offset -= seg->data_len;
		seg = seg->next;
	}
	copy_len = seg->data_len - offset;
	seg_buf = rte_pktmbuf_mtod_offset(seg, char *, offset);
	while (len > copy_len) {
		rte_memcpy(seg_buf, buf, (size_t) copy_len);
		len -= copy_len;
		buf = ((char*) buf + copy_len);
		seg = seg->next;
		seg_buf = rte_pktmbuf_mtod(seg, char *);
		copy_len = seg->data_len;
	}
	rte_memcpy(seg_buf, buf, (size_t) len);
}

static inline void
copy_buf_to_pkt(void* buf, unsigned len, struct rte_mbuf *pkt, unsigned offset)
{
	if (offset + len <= pkt->data_len) {
		rte_memcpy(rte_pktmbuf_mtod_offset(pkt, char *, offset),
			buf, (size_t) len);
		return;
	}
	copy_buf_to_pkt_segs(buf, len, pkt, offset);
}

static void
setup_pkt_udp_ip_headers(struct ipv4_hdr *ip_hdr,
			 struct udp_hdr *udp_hdr,
			 uint16_t pkt_data_len)
{
	uint16_t *ptr16;
	uint32_t ip_cksum;
	uint16_t pkt_len;

	/*
 * 	 * Initialize UDP header.
 * 	 	 */
	pkt_len = (uint16_t) (pkt_data_len + sizeof(struct udp_hdr));
	udp_hdr->src_port = rte_cpu_to_be_16(UDP_SRC_PORT);
	udp_hdr->dst_port = rte_cpu_to_be_16(UDP_DST_PORT);
	udp_hdr->dgram_len      = RTE_CPU_TO_BE_16(pkt_len);
	udp_hdr->dgram_cksum    = 0; /* No UDP checksum. */

	/*
 * 	 * Initialize IP header.
 * 	 	 */
	pkt_len = (uint16_t) (pkt_len + sizeof(struct ipv4_hdr));
	ip_hdr->version_ihl   = IP_VHL_DEF;
	ip_hdr->type_of_service   = 0;
	ip_hdr->fragment_offset = 0;
	ip_hdr->time_to_live   = IP_DEFTTL;
	ip_hdr->next_proto_id = IPPROTO_UDP;
	ip_hdr->packet_id = 0;
	ip_hdr->total_length   = RTE_CPU_TO_BE_16(pkt_len);
	ip_hdr->src_addr = rte_cpu_to_be_32(IP_SRC_ADDR);
	ip_hdr->dst_addr = rte_cpu_to_be_32(IP_DST_ADDR);

	/*
 * 	 * Compute IP header checksum.
 * 	 	 */
	ptr16 = (unaligned_uint16_t*) ip_hdr;
	ip_cksum = 0;
	ip_cksum += ptr16[0]; ip_cksum += ptr16[1];
	ip_cksum += ptr16[2]; ip_cksum += ptr16[3];
	ip_cksum += ptr16[4];
	ip_cksum += ptr16[6]; ip_cksum += ptr16[7];
	ip_cksum += ptr16[8]; ip_cksum += ptr16[9];


 //Reduce 32 bit checksum to 16 bits and complement it.
	
	ip_cksum = ((ip_cksum & 0xFFFF0000) >> 16) +
		(ip_cksum & 0x0000FFFF);
	if (ip_cksum > 65535)
		ip_cksum -= 65535;
	ip_cksum = (~ip_cksum) & 0x0000FFFF;
	if (ip_cksum == 0)
		ip_cksum = 0xFFFF;

	ip_hdr->hdr_checksum = (uint16_t) ip_cksum;
}

/*
 * Initializes a given port using global settings and with the RX buffers
 * coming from the mbuf_pool passed as a parameter.
 */
static inline int
port_init(uint16_t port, struct rte_mempool *mbuf_pool)
{
	struct rte_eth_conf port_conf = port_conf_default;
	const uint16_t rx_rings = 1, tx_rings = 1;
	uint16_t nb_rxd = RX_RING_SIZE;
	uint16_t nb_txd = TX_RING_SIZE;
	int retval;
	uint16_t q;
	struct rte_eth_dev_info dev_info;
	struct rte_eth_txconf txconf;

	if (!rte_eth_dev_is_valid_port(port))
		return -1;

	rte_eth_dev_info_get(port, &dev_info);
	if (dev_info.tx_offload_capa & DEV_TX_OFFLOAD_MBUF_FAST_FREE)
		port_conf.txmode.offloads |=
			DEV_TX_OFFLOAD_MBUF_FAST_FREE;

	/* Configure the Ethernet device. */
	retval = rte_eth_dev_configure(port, rx_rings, tx_rings, &port_conf);
	if (retval != 0)
		return retval;

	retval = rte_eth_dev_adjust_nb_rx_tx_desc(port, &nb_rxd, &nb_txd);
	if (retval != 0)
		return retval;

	/* Allocate and set up 1 RX queue per Ethernet port. */
/*
 * for (q = 0; q < rx_rings; q++) {
		retval = rte_eth_rx_queue_setup(port, q, nb_rxd,
				rte_eth_dev_socket_id(port), NULL, mbuf_pool);
		if (retval < 0)
			return retval;
	}
*/

	txconf = dev_info.default_txconf;
	txconf.offloads = port_conf.txmode.offloads;
	/* Allocate and set up 1 TX queue per Ethernet port. */
	for (q = 0; q < tx_rings; q++) {
		retval = rte_eth_tx_queue_setup(port, q, nb_txd,
				rte_eth_dev_socket_id(port), &txconf);
		if (retval < 0)
			return retval;
	}

	/* Start the Ethernet port. */
	retval = rte_eth_dev_start(port);
	if (retval < 0)
		return retval;

	/* Display the port MAC address. */
	rte_eth_macaddr_get(port, &my_addr);
	printf("Port %u MAC: %02" PRIx8 " %02" PRIx8 " %02" PRIx8
			   " %02" PRIx8 " %02" PRIx8 " %02" PRIx8 "\n",
			port,
			my_addr.addr_bytes[0], my_addr.addr_bytes[1],
			my_addr.addr_bytes[2], my_addr.addr_bytes[3],
			my_addr.addr_bytes[4], my_addr.addr_bytes[5]);

	/* Enable RX in promiscuous mode for the Ethernet device. */
	rte_eth_promiscuous_enable(port);

	return 0;
}

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

static __inline__ unsigned long long rdtsc(void)
{
  unsigned hi, lo;
  __asm__ __volatile__ ("rdtsc" : "=a"(lo), "=d"(hi));
  return ( (unsigned long long)lo)|( ((unsigned long long)hi)<<32 );
}

void IPG_wait()
{
	unsigned long long time1,time2;
	
//	struct timespec time1,time2,delta;
	if(IPG>0){
 
/* this was way too slow... */       	
//		clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &time1);
//	        do {
//			clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &time2);
//			delta=diff(time1,time2);
//	        }
//		while (delta.tv_nsec<IPG);

		time1=rdtsc();
		do {
			time2=rdtsc();
		}
		while (time2-time1<IPG);	
	}
}

/*
 * The lcore main polled task
 */
static __attribute__((noreturn)) void lcore_main(struct rte_mempool *mbp)
{
	struct rte_mbuf *pkt;
	struct rte_mbuf *pkts_burst[1];
	
        union {
                uint64_t as_int;
                struct ether_addr as_addr;
        } dst_eth_addr;

	struct ether_hdr eth_hdr;
	time_t TheTime=0;
	pkt = rte_mbuf_raw_alloc(mbp);  
	if(pkt == NULL) {printf("trouble at rte_mbuf_raw_alloc\n");}
	rte_pktmbuf_reset_headroom(pkt);
	pkt->data_len = TX_PACKET_LENGTH;

	// set up dst MAC	
	dst_eth_addr.as_int=rte_cpu_to_be_64(DST_MAC);
	ether_addr_copy(&dst_eth_addr,&eth_hdr.d_addr);
	ether_addr_copy(&my_addr, &eth_hdr.s_addr);
	eth_hdr.ether_type = rte_cpu_to_be_16(ETHER_TYPE_IPv4);

	copy_buf_to_pkt(&eth_hdr, sizeof(eth_hdr), pkt, 0);
	copy_buf_to_pkt(&pkt_ip_hdr, sizeof(pkt_ip_hdr), pkt, sizeof(struct ether_hdr));
	copy_buf_to_pkt(&pkt_udp_hdr, sizeof(pkt_udp_hdr), pkt,
				sizeof(struct ether_hdr) +
				sizeof(struct ipv4_hdr));

// Add some pkt fields

	pkt->nb_segs = 1;
	pkt->pkt_len = pkt->data_len;
	pkt->ol_flags = 0;

	char rtp_hdr[4] = {0x80, 0x60, 0x0, 0x0 };
	rtp_hdr[2]=(sn/256);
	rtp_hdr[3]=(sn%256);
	sn=(sn+1)%32768;

	rtp_hdr[1]=0x60;
	if(sn==0){	
		TheTime=time(NULL);
		if(((TheTime % 60)==0) && (TheTime != dontmark))
		{	
			// mark 
			rtp_hdr[1]=0xE0;
			dontmark=TheTime; // just do it once
		}
	}
	copy_buf_to_pkt(&rtp_hdr, sizeof(rtp_hdr), pkt, 
				sizeof(struct ether_hdr) +
                                sizeof(struct ipv4_hdr) + 
				sizeof(struct udp_hdr));

	pkts_burst[0] = pkt;
	// make sure packet sends	
	while(rte_eth_tx_burst(0,0,pkts_burst,1) != 1){};	
	IPG_wait();
}

void process_args(int argc, char **argv)
{
	int c,mac_flag=0,ip_src_flag=0,ip_dst_flag=0;

	while ((c = getopt(argc, argv, "m:s:d:h:g:")) != -1)
                switch(c) {
                case 'm':
                        // note, not quite sure why last two bytes are zero, but that is how DPDK likes it
                        DST_MAC=0ULL;
                        DST_MAC=string_to_mac(optarg)<<16;
                        mac_flag=1;
                        break;
                case 's':
                        IP_SRC_ADDR=string_to_ip(optarg);
                        ip_src_flag=1;
                        break;
                case 'd':
                        IP_DST_ADDR=string_to_ip(optarg);
                        ip_dst_flag=1;
                        break;
		case 'g':
			IPG=strtol(optarg,(char **)NULL,10);
			break;
                case 'h':
                        printf("usage -- -m [dst MAC] -s [src IP] -d [dst IP]\n");
                        exit(0);
                        break;
                }

        if(mac_flag==0) {
                fprintf(stderr, "missing -m for destination MAC adress\n");
                exit(1);
        }
        if(ip_src_flag==0) {
                fprintf(stderr, "missing -s for IP source adress\n");
                exit(1);
        }
        if(ip_dst_flag==0) {
                fprintf(stderr, "missing -d for IP destination adress\n");
                exit(1);
        }
}

/*
 * The main function, which does initialization and calls the per-lcore
 * functions.
 */
int
main(int argc, char *argv[])
{
	struct rte_mempool *mbuf_pool;
	uint16_t portid;

	/* Initialize the Environment Abstraction Layer (EAL). */
	int ret = rte_eal_init(argc, argv);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Error with EAL initialization\n");

	argc -= ret;
	argv += ret;

	process_args(argc,argv);

	/* Creates a new mempool in memory to hold the mbufs. */
	mbuf_pool = rte_pktmbuf_pool_create("MBUF_POOL", NUM_MBUFS,
		MBUF_CACHE_SIZE, 0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());

	if (mbuf_pool == NULL)
		rte_exit(EXIT_FAILURE, "Cannot create mbuf pool\n");

	/* Initialize all ports. */
	RTE_ETH_FOREACH_DEV(portid)
		if (port_init(portid, mbuf_pool) != 0)
			rte_exit(EXIT_FAILURE, "Cannot init port %"PRIu16 "\n",
					portid);

	uint16_t pkt_data_len;

	pkt_data_len = (uint16_t) (TX_PACKET_LENGTH - (sizeof(struct ether_hdr) +
						    sizeof(struct ipv4_hdr) +
						    sizeof(struct udp_hdr)));
	setup_pkt_udp_ip_headers(&pkt_ip_hdr, &pkt_udp_hdr, pkt_data_len);


	/* Call lcore_main on the master core only. */
	lcore_main(mbuf_pool);

	return 0;
}
