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

#define BUFSIZE 828 

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

void print_time()
{
	time_t     now;
	struct tm *ts;
	char       buf[80];

	/* Get the current time */
	now = time(NULL);

	/* Format and print the time, "ddd yyyy-mm-dd hh:mm:ss zzz" */
	ts = localtime(&now);
	strftime(buf, sizeof(buf), "%a %Y-%m-%d %H:%M:%S %Z", ts);

	printf("%s:",buf);
}


int main(int argc, char **argv) {
    int sockfd, portno, n, cliaddrlen;
    struct sockaddr_in serveraddr,cliaddr;
    char buf[BUFSIZE];
    struct timespec the_time;
    long last_time=0;
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
		printf("DROP before: %d\n",this_sn);
		fflush(stdout);	
	}	
	if((buf[1] & 0xff) == 0xe0){
		print_time();
                printf("MARK\n");
                fflush(stdout);
        }
	last_sn=this_sn;
	last_time=the_time.tv_nsec;
    }
}
 
