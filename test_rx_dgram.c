// UDP receive test
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
#include <sys/time.h>
#include <math.h>
#include <errno.h>

#define BUFSIZE 8900

/* 
 *  * error - wrapper for perror
 *   */
void error(char *msg) {
    perror(msg);
    exit(0);
}

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


int main(int argc, char **argv) {
    int sockfd, portno, n, cliaddrlen;
    struct sockaddr_in serveraddr,cliaddr;
    char buf[BUFSIZE];
    struct timespec the_time;
    uint this_sn,last_sn=-1;

    /* check command line arguments */
    if (argc != 2) {
       fprintf(stderr,"usage: %s <port>\n", argv[0]);
       exit(0);
    }
    portno = atoi(argv[1]);

    /* socket: create the socket */
    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) 
        error("ERROR opening socket");

    memset(&serveraddr, 0, sizeof(serveraddr)); 
    memset(&cliaddr, 0, sizeof(cliaddr)); 
      
    // Filling server information 
    serveraddr.sin_family    = AF_INET; // IPv4 
    serveraddr.sin_addr.s_addr = INADDR_ANY; 
    serveraddr.sin_port = htons(portno); 

    /* set large buffer */
    long buf_size = 4294967295; // 2^32-1
    if (setsockopt(sockfd, SOL_SOCKET, SO_RCVBUF, &n, buf_size) == -1)
                printf("ERROR set receive buffer size %s", strerror(errno));

    /* bind the socket */
    if (bind(sockfd, (const struct sockaddr *)&serveraddr,sizeof(serveraddr)) <0)
        error("ERROR binding socket");

    bzero(buf, BUFSIZE);

    print_time();
    printf("START\n");
    fflush(stdout);
    
    while(1)
    {
	n = recvfrom(sockfd, buf, BUFSIZE, 0, (struct sockaddr*) &cliaddr, &cliaddrlen);
	if (n < 0)
		error("ERROR in sendto"); 
	clock_gettime(CLOCK_REALTIME, &the_time);	
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
}
 
