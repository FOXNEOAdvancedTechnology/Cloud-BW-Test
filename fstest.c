// Receive RTP flow, look for dropped packets based on RTP sequence number
// uses F-Stack https://github.com/F-Stack/f-stack
//
// Thomas Edwards, FOX
// (based on example main.c program from f-stack github)
//

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <strings.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <errno.h>
#include <assert.h>
#include <time.h>
#include <sys/time.h>

#include <unistd.h>

#include "ff_config.h"
#include "ff_api.h"

#define MAX_EVENTS 512
#define BUFSIZE 8900

//#define DEBUG 1

/* kevent set */
struct kevent kevSet;
/* events */
struct kevent events[MAX_EVENTS];
/* kq */
int kq;
int sockfd;

char buf[BUFSIZE];
int n;
struct sockaddr_in cliaddr;
int cliaddrlen;
uint this_sn,last_sn=-1;

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

int loop(void *arg)
{
    /* Wait for events to happen */
    unsigned nevents = ff_kevent(kq, NULL, 0, events, MAX_EVENTS, NULL);
    unsigned i;

    if(nevents>1) { printf("In loop, recieved %d events\n",nevents);}
    for (i = 0; i < nevents; ++i) {
        struct kevent event = events[i];
        int clientfd = (int)event.ident;

        if (clientfd == sockfd) {
#if DEBUG
   		printf("clientfd == sockfd\n"); 
#endif
		int n = ff_recvfrom(sockfd, buf, BUFSIZE, 0, (struct linux_sockaddr*) &cliaddr, &cliaddrlen);
	        if (n < 0)
			{ error("ERROR in sendto"); }
#if DEBUG
		printf("ff_recvfrom %d bytes:: %s\n",n,buf); 
#endif
		this_sn=((buf[2] &0xff) << 8 ) | (buf[3] & 0xff);
		if((this_sn-last_sn != 1) && (this_sn-last_sn != -32767) &&(last_sn != -1))
		{
			print_time();
			printf("DROP,%d,%d\n",last_sn,this_sn);
			fflush(stdout);	
		}	
		if((buf[1] & 0xff) == 0xe0){
			print_time();
			printf("MARK\n");
			fflush(stdout);
		}
		last_sn=this_sn;
	}
	else { printf("Weird, clientd != sockfd\n"); exit(1); }
	return 0;
	}
}

int main(int argc, char * argv[])
{
    ff_init(argc, argv);

    sockfd = ff_socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    printf("sockfd:%d\n", sockfd);
    if (sockfd < 0) {
        printf("ff_socket failed\n");
        exit(1);
    }

    struct sockaddr_in my_addr;
    bzero(&my_addr, sizeof(my_addr));
    my_addr.sin_family = AF_INET;
    my_addr.sin_port = htons(6666);
    my_addr.sin_addr.s_addr = htonl(INADDR_ANY);

    int ret = ff_bind(sockfd, (struct linux_sockaddr *)&my_addr, sizeof(my_addr));
    if (ret < 0) {
        printf("ff_bind failed\n");
        exit(1);
    }
#if DEBUG
    printf("ff_bind successful\n");
#endif

    struct timeval read_timeout;
    read_timeout.tv_sec = 0;
    read_timeout.tv_usec = 1;
    ff_setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &read_timeout, sizeof read_timeout);

    EV_SET(&kevSet, sockfd, EVFILT_READ, EV_ADD, 0, MAX_EVENTS, NULL);
#if DEBUG
    printf("EV_SET kevSet\n");
#endif

    assert((kq = ff_kqueue()) > 0);
#if DEBUG
    printf("Called ff_kqeue\n");
#endif

    /* Update kqueue */
    ff_kevent(kq, &kevSet, 1, NULL, 0, NULL);
#if DEBUG
    printf("called ff_kevent on kevSet\n");
#endif

    ff_run(loop, NULL);
    return 0;
}
