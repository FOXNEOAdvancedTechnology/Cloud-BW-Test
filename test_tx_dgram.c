// RTP/UDP sender test
// AF_INET/SOCK_DGRAM 
// 
#include <stdio.h> 
#include <stdlib.h> 
#include <unistd.h> 
#include <string.h> 
#include <sys/types.h> 
#include <sys/socket.h> 
#include <arpa/inet.h> 
#include <netinet/in.h> 
#include <netdb.h> 
#include <time.h>

#define BUFSIZE 820 
#define IPG 57600 

/* 
 *  * error - wrapper for perror
 *   */
void error(char *msg) {
    perror(msg);
    exit(0);
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

int main(int argc, char **argv) {
    int sockfd, portno, n;
    int serverlen;
    struct sockaddr_in serveraddr;
    struct hostent *server;
    char *hostname;
    char buf[BUFSIZE];
    struct timespec time1, time2, delta;
    int sn=0;

    /* check command line arguments */
    if (argc != 3) {
       fprintf(stderr,"usage: %s <hostname> <port>\n", argv[0]);
       exit(0);
    }
    hostname = argv[1];
    portno = atoi(argv[2]);

    /* load up packet */
    FILE *f;

    memset(buf, 0, BUFSIZE);

    buf[0]=0x80;
    buf[1]=0x60;

    /* socket: create the socket */
    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) 
        error("ERROR opening socket");

    /* gethostbyname: get the server's DNS entry */
    server = gethostbyname(hostname);
    if (server == NULL) {
        fprintf(stderr,"ERROR, no such host as %s\n", hostname);
        exit(0);
    }

    /* build the server's Internet address */
    bzero((char *) &serveraddr, sizeof(serveraddr));
    serveraddr.sin_family = AF_INET;
    bcopy((char *)server->h_addr, 
	  (char *)&serveraddr.sin_addr.s_addr, server->h_length);
    serveraddr.sin_port = htons(portno);

    serverlen = sizeof(serveraddr);

    long dontmark=0;

    while(1) 
    {
        buf[2]=(sn/256);
	buf[3]=(sn%256);
	if(((time2.tv_sec % 60)==0) && (time2.tv_sec != dontmark))
        {
		// mark 
		buf[1]=0xE0;
		dontmark=time2.tv_sec; // just do it once
//		printf("Mark!\n");
	}
	else
	{
		// don't mark
		buf[1]=0x60;
	}
	n = sendto(sockfd, buf, BUFSIZE, 0, (struct sockaddr*) &serveraddr, serverlen);
	sn=(sn+1)%32768;
	clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &time1);
	if (n < 0)	
		error("ERROR in sendto"); 
   	do {
		clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &time2);
		delta=diff(time1,time2);
	}
	while (delta.tv_nsec<IPG);
    }
}
 
