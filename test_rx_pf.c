#include <unistd.h>
#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/ip.h>
#include <linux/filter.h>
#include <linux/udp.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <net/if.h>
#include <netinet/ether.h>
#include <time.h>

#define ETHER_TYPE	0x0800

#define DEFAULT_IF	"eth0"
#define BUF_SIZ		1024

#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))
// sudo tcpdump -i eth0 -dd dst port 6666
struct sock_filter code[] = {
{ 0x28, 0, 0, 0x0000000c },
{ 0x15, 0, 6, 0x000086dd },
{ 0x30, 0, 0, 0x00000014 },
{ 0x15, 2, 0, 0x00000084 },
{ 0x15, 1, 0, 0x00000006 },
{ 0x15, 0, 13, 0x00000011 },
{ 0x28, 0, 0, 0x00000038 },
{ 0x15, 10, 11, 0x00001a0a },
{ 0x15, 0, 10, 0x00000800 },
{ 0x30, 0, 0, 0x00000017 },
{ 0x15, 2, 0, 0x00000084 },
{ 0x15, 1, 0, 0x00000006 },
{ 0x15, 0, 6, 0x00000011 },
{ 0x28, 0, 0, 0x00000014 },
{ 0x45, 4, 0, 0x00001fff },
{ 0xb1, 0, 0, 0x0000000e },
{ 0x48, 0, 0, 0x00000010 },
{ 0x15, 0, 1, 0x00001a0a },
{ 0x6, 0, 0, 0x00040000 },
{ 0x6, 0, 0, 0x00000000 }
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
        strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", ts);

        printf("%s,",buf);
}

int main(int argc, char *argv[])
{
	char sender[INET6_ADDRSTRLEN];
	int sockfd, ret, i;
	int sockopt;
	ssize_t numbytes;
	struct ifreq ifopts;	/* set promiscuous mode */
	struct ifreq if_ip;	/* get ip addr */
	struct sockaddr_storage their_addr;
	uint8_t buf[BUF_SIZ];
	char ifName[IFNAMSIZ];
	uint this_sn,last_sn=-1;
	struct timespec the_time;

	struct sock_fprog bpf = {
       	  .len = ARRAY_SIZE(code),
       	          .filter = code,
	};	
	/* Get interface name */
	if (argc > 1)
		strcpy(ifName, argv[1]);
	else
		strcpy(ifName, DEFAULT_IF);

	/* Header structures */
	struct ether_header *eh = (struct ether_header *) buf;
	struct iphdr *iph = (struct iphdr *) (buf + sizeof(struct ether_header));
	struct udphdr *udph = (struct udphdr *) (buf + sizeof(struct iphdr) + sizeof(struct ether_header));

	memset(&if_ip, 0, sizeof(struct ifreq));

	/* Open PF_PACKET socket, listening for EtherType ETHER_TYPE */
//	if ((sockfd = socket(PF_PACKET, SOCK_RAW, htons(ETHER_TYPE))) == -1) {
	if ((sockfd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_IP))) == -1) {
		perror("listener: socket");	
		return -1;
	}

	/* Set interface to promiscuous mode - do we need to do this every time? */
	strncpy(ifopts.ifr_name, ifName, IFNAMSIZ-1);
	ioctl(sockfd, SIOCGIFFLAGS, &ifopts);
	ifopts.ifr_flags |= IFF_PROMISC;
	ioctl(sockfd, SIOCSIFFLAGS, &ifopts);
	/* Allow the socket to be reused - incase connection is closed prematurely */
	if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &sockopt, sizeof sockopt) == -1) {
		perror("setsockopt");
		close(sockfd);
		exit(EXIT_FAILURE);
	}
	/* Bind to device */
	if (setsockopt(sockfd, SOL_SOCKET, SO_BINDTODEVICE, ifName, IFNAMSIZ-1) == -1)	{
		perror("SO_BINDTODEVICE");
		close(sockfd);
		exit(EXIT_FAILURE);
	}

	/* Linux packet filter */
	ret = setsockopt(sockfd, SOL_SOCKET, SO_ATTACH_FILTER, &bpf, sizeof(bpf));
	if (ret < 0) {
                perror("SO_ATTACH_FILTER");
                close(sockfd);
                exit(EXIT_FAILURE);
	}

	print_time();
	printf("START\n");
repeat:	//printf("listener: Waiting to recvfrom...\n");
	numbytes = recvfrom(sockfd, buf, BUF_SIZ, 0, NULL, NULL);
	//printf("listener: got packet %lu bytes\n", numbytes);

	/* Check the packet is for me */
/*
	if (eh->ether_dhost[0] == DEST_MAC0 &&
			eh->ether_dhost[1] == DEST_MAC1 &&
			eh->ether_dhost[2] == DEST_MAC2 &&
			eh->ether_dhost[3] == DEST_MAC3 &&
			eh->ether_dhost[4] == DEST_MAC4 &&
			eh->ether_dhost[5] == DEST_MAC5 &&
			ntohs(udph->len)==6666) {
		printf("Correct destination MAC address\n");
	} else {
		printf("Wrong destination MAC: %x:%x:%x:%x:%x:%x\n",
						eh->ether_dhost[0],
						eh->ether_dhost[1],
						eh->ether_dhost[2],
						eh->ether_dhost[3],
						eh->ether_dhost[4],
						eh->ether_dhost[5]);
		ret = -1;
		goto done;
	}

*/
	// look for right UDP dest port
	/*	
	if(ntohs(udph->dest)!=6666){
		goto done;
	}
	*/

	/* Get source IP */
	//((struct sockaddr_in *)&their_addr)->sin_addr.s_addr = iph->saddr;
	//inet_ntop(AF_INET, &((struct sockaddr_in*)&their_addr)->sin_addr, sender, sizeof sender);

	/* Look up my device IP addr if possible */
	// strncpy(if_ip.ifr_name, ifName, IFNAMSIZ-1);
	//if (ioctl(sockfd, SIOCGIFADDR, &if_ip) >= 0) { /* if we can't check then don't */
	//	printf("Source IP: %s\n My IP: %s\n", sender, 
	//			inet_ntoa(((struct sockaddr_in *)&if_ip.ifr_addr)->sin_addr));
	//	/* ignore if I sent it */
	//	if (strcmp(sender, inet_ntoa(((struct sockaddr_in *)&if_ip.ifr_addr)->sin_addr)) == 0)	{
	//		printf("but I sent it :(\n");
	//		ret = -1;
	//		goto done;
	//	}
	//}

	/* UDP payload length */
	// ret = ntohs(udph->len) - sizeof(struct udphdr);

        clock_gettime(CLOCK_REALTIME, &the_time);
        this_sn=((buf[44] &0xff) << 8 ) | (buf[45] & 0xff);
        if((this_sn-last_sn != 1) && (this_sn-last_sn != -32767) &&(last_sn != -1))
        {
                print_time();
                printf("DROP,%d,%d\n",last_sn,this_sn);
                fflush(stdout);
        }
        if((buf[43] & 0xff) == 0xe0){
                print_time();
                printf("MARK\n");
                fflush(stdout);
        }
        last_sn=this_sn;

	// Print packet 
	/*
	printf("\tData:");
	for (i=0; i<numbytes; i++) printf("%02x:", buf[i]);
	printf("\n");
	if(ntohs(udph->dest)==6666){
		printf("**********************************************************************\n");
	}
	printf("UDP DST %ld\n",ntohs(udph->dest));
	*/

done:	goto repeat;

	close(sockfd);
	return ret;
}
