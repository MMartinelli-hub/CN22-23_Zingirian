#include <arpa/inet.h>
#include<errno.h>
#include<stdio.h>
#include<signal.h>
#include <sys/types.h>
#include <sys/time.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <linux/if_packet.h>
#include <net/ethernet.h> /* the L2 protocols */
#include <net/if.h>
#include <strings.h>
#include <string.h>
#include <stdlib.h>
#include <poll.h>
#include <time.h>

#define CACHE_SZ	100
unsigned char broadcast[6]={0xFF,0xFF,0xFF, 0xFF, 0xFF, 0xFF};
unsigned char mymac[6] = { 0xf2,0x3c,0x91,0xDB, 0xC2, 0x98};
unsigned char myip[4] = { 88,80,187,84 };
unsigned char netmask[4]={255,255,255,0};
unsigned char gateway[4]={88,80,187,1};

struct ethernet_frame {
	unsigned char dst[6];
	unsigned char src[6];
	unsigned short type;
	unsigned char payload[1];
};

struct arp_packet {
	unsigned short haddr ;
	unsigned short paddr ;
	unsigned char hlen;
	unsigned char plen;
	unsigned short op;
	unsigned char srcmac[6];
	unsigned char srcip[4];
	unsigned char dstmac[6];
	unsigned int dstip;
};

void forge_eth( struct ethernet_frame * eth, unsigned char *dst, unsigned short type   );
#define MAXFRAME 10000
#define TIMER_USECS 100000
int pkts=0;
struct sigaction action_io, action_timer;
sigset_t mymask;
unsigned char l2buffer[MAXFRAME];
struct sockaddr_ll;
struct pollfd fds[1];
int fdfl;
long long int tick=0;
int unique_s;
int fl;
struct sockaddr_ll sll;

struct arp_cache{
	unsigned int ip;
	unsigned char mac[6];
	unsigned int t_created;
	unsigned char occupied;
}cache[CACHE_SZ];

int printbuf(void * b, int size){
	int i;
	unsigned char * c = (unsigned char *) b;
	for(i=0;i<size;i++)
		printf("%.2x(%.3d) ", c[i],c[i]);
	printf("\n");
}

int arp_resolve(unsigned int ipaddr, unsigned char * mac){

	int len,t;
	unsigned char buffer[1000];
	struct ethernet_frame * eth;
	struct arp_packet * arp;

	for(int i = 0; i < CACHE_SZ; i ++){
		if(cache[i].occupied)
			if(cache[i].ip == ipaddr){
				for(int k = 0; k < 6; k ++)	mac[k] = cache[i].mac[k];
				return 0;
			}
	}

	eth = (struct ethernet_frame *) buffer;
	arp = (struct arp_packet * ) eth->payload;
	forge_eth(eth,broadcast,0x0806);
	arp->haddr = htons(1); arp->paddr = htons(0x0800);
	arp->hlen = 6; arp->plen = 4; arp->op = htons(1);
	for(int i=0; i<6; i++) arp->srcmac[i]=mymac[i];
	for(int i=0; i<4; i++) arp->srcip[i]=myip[i];
	for(int i=0; i<6; i++) arp->dstmac[i]=0;
	arp->dstip = ipaddr;
	printf("ARP Request");
	//for(int i=0; i<22;i++) buffer[14+28+i]=0;
	//printbuf(buffer,64);
	for(int i=0; i<sizeof(struct sockaddr_ll); i++) ((char*)&sll)[i]=0;
	sll.sll_family=AF_PACKET;
	sll.sll_ifindex = if_nametoindex("eth0");
	len = sizeof(struct sockaddr_ll);
	t = sendto(unique_s, buffer, 64, 0 ,(struct sockaddr *) &sll, len);
	if ( t == -1) {perror("sendto Failed"); return 1;}
	//printf("ARP Request %d bytes sent\n",t);

	unsigned int time = tick;

	while(pause()){

		for(int i = 0; i < CACHE_SZ; i ++){
			if(cache[i].occupied)
				if(cache[i].ip == ipaddr){
					for(int k = 0; k < 6; k ++)	mac[k] = cache[i].mac[k];
					return 0;
				}
		}

		if(tick - time >= 3)
			return -1;
	}
}

void forge_eth( struct ethernet_frame * eth, unsigned char *dst, unsigned short type   )
{
	for(int i=0;i<6;i++) eth->dst[i] = dst[i];
	for(int i=0;i<6;i++) eth->src[i] = mymac[i];
	eth->type = htons(type);
}

void mytimer(int number){
	int i;
	if(-1 == sigprocmask(SIG_BLOCK, &mymask, NULL)){perror("sigprocmask"); return ;}
	fl++;
	tick++;
	if(tick%(1000000/TIMER_USECS)==0){
		printf("Mytimer Called: pkts =%d\n",pkts);
		pkts = 0;
	}
	if (fl > 1) printf("Overlap Timer\n");
	fl--;
	if(-1 == sigprocmask(SIG_UNBLOCK, &mymask, NULL)){perror("sigprocmask"); return ;}

	for(i = 0; i < CACHE_SZ; i ++){
		if(cache[i].occupied){
			if(tick - cache[i].t_created >=300)
				cache[i].occupied = 0;
		}
	}
}

void myio(int number)
{
	int len, size;
	struct ethernet_frame *eth = (struct ethernet_frame *)l2buffer;
	struct arp_packet *arp = (struct arp_packet *)eth->payload;

	if(-1 == sigprocmask(SIG_BLOCK, &mymask, NULL)){perror("sigprocmask"); return ;}
	fl++;
	if (fl > 1) printf("Overlap (%d) in myio\n",fl);
	if( poll(fds,1,0) == -1) { perror("Poll failed"); return; }
	if (fds[0].revents & POLLIN){
		len = sizeof(struct sockaddr_ll);
		//printf("Polled\n");
		while ( 0 <= (size = recvfrom(unique_s,l2buffer,MAXFRAME,0, (struct sockaddr *) &sll,&len))){
			pkts++;//printf("pkt received\n");

			if ( eth->type == htons(0x0806))
				if(arp->op == htons(2))
				{
					//printf("ARP response:");
					//printbuf(buffer, t );

					for(int i = 0; i < CACHE_SZ; i ++){
						if(!cache[i].occupied){
							cache[i].occupied = 1;
							cache[i].t_created = tick;
							for(int j=0;j<4;j++) ((unsigned char *)(&cache[i].ip))[j] = arp->srcip[j];
							for(int j=0;j<6;j++) cache[i].mac[j] = arp->srcmac[j];
							break;
						}
					}
				}
			//printf("No ARP response received\n");
		}
		if ( errno != EAGAIN ) { perror("Packet recvfrom Error\n"); }
	}
	fds[0].events= POLLIN|POLLOUT;
	fds[0].revents=0;
	if (fl > 1) printf("Overlap (%d) in myio\n",fl);
	//printbuf(eth,size);
	fl--;
	if(-1 == sigprocmask(SIG_UNBLOCK, &mymask, NULL)){perror("sigprocmask"); return ;
	}
}

int main(int argc, char **argv)
{
	unsigned char target_ip[4] = {88, 80, 187, 1};
	unsigned char target_mac[6];
	clock_t start;
	fl = 0;
	struct itimerval myt;
	action_io.sa_handler = myio;
	action_timer.sa_handler = mytimer;
	sigaction(SIGIO, &action_io, NULL);
	sigaction(SIGALRM, &action_timer, NULL);
	unique_s = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	if (unique_s == -1 ) { perror("Socket Failed"); return 1;}
	if (-1 == fcntl(unique_s, F_SETOWN, getpid())){ perror("fcntl setown"); return 1;}
	fdfl = fcntl(unique_s, F_GETFL, NULL); if(fdfl == -1) { perror("fcntl f_getfl"); return 1;}
	fdfl = fcntl(unique_s, F_SETFL,fdfl|O_ASYNC|O_NONBLOCK); if(fdfl == -1) { perror("fcntl f_setfl"); return 1;}
	fds[0].fd = unique_s;
	fds[0].events= POLLIN|POLLOUT;
	fds[0].revents=0;
	sll.sll_family = AF_PACKET;
	sll.sll_ifindex = if_nametoindex("eth0");
	myt.it_interval.tv_sec=1; 
	myt.it_interval.tv_usec=0; 
	myt.it_value.tv_sec=1;    
	myt.it_value.tv_usec=0;
	if( -1 == sigemptyset(&mymask)) {perror("Sigemtpyset"); return 1;}
	if( -1 == sigaddset(&mymask, SIGALRM)){perror("Sigaddset");return 1;}
	if( -1 == sigaddset(&mymask, SIGIO)){perror("Sigaddset");return 1;}
	if(-1 == sigprocmask(SIG_UNBLOCK, &mymask, NULL)){perror("sigprocmask"); return -1;}
	if ( -1 == setitimer(ITIMER_REAL, &myt, NULL)){perror("Setitimer"); return 1; }

	for(unsigned int i = 0; i < 2; i ++)
		for(target_ip[3] = atoi(argv[1]); target_ip[3] < atoi(argv[2]); target_ip[3] ++){
			printf("resolving: 88.80.187.%d:", target_ip[3]);
			if(!arp_resolve(*(unsigned int *)target_ip, target_mac))
				printbuf(target_mac, 6);
			else printf("unresolved ip\n");
		}
}
