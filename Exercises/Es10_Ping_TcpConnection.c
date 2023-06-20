/*
   Author: Marco Martinelli
   Implementation Date: 15/06/2023
   Time Took: 46 min 

# IDEA #
- We define a tcp_segment struct
- We define a tcp_pseudo for the tcp pseudo header (used to compute the checksum)
- We modify the main
   > the forge ip protocol parameter is set to 6
   > the intercept is changed so to intercept TCP responses

   All the modifications to the code can be found by searching for '##'
*/

#include <sys/types.h>          /* See NOTES */
#include <arpa/inet.h>
#include <strings.h>
#include <string.h>
#include <sys/socket.h>
#include <linux/if_packet.h>
#include <net/ethernet.h> /* the L2 protocols */
#include <net/if.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

unsigned char broadcast[6]={0xFF,0xFF,0xFF,0xFF,0xFF,0xFF};
unsigned char mymac[6] = { 0xbe,0x63,0xb2,0xfb,0x8d,0x33} ; 
unsigned char myip[4] = { 89,40,142,15 }; 
unsigned char netmask[4]={255,255,255,0};
unsigned char gateway[4]={89,40,142,1};

//##
struct tcp_segment {
   unsigned short sport;
   unsigned short dport;
   unsigned int seq;
   unsigned int ack;
   unsigned char dataoff_res;
   unsigned char flags;
   unsigned short window;
   unsigned short checksum;
   unsigned short urg;
};

//##
int forge_tcp(struct tcp_segment* tcp, unsigned short sport, unsigned int seq) {
   tcp->sport = htons(sport); //to be passed as rand each time
   tcp->dport = htons(80); //default web service port
   tcp->seq = htonl(seq); //to be passed as rand each time
   tcp->ack = 0; 
   tcp->dataoff_res = 0x50; //min length packet = 5 x 32 bits, reserved must be set at 0
   tcp->flags = 2; //SYN is flag 2
   tcp->window = 0xFFFF; //imposed
   tcp->checksum = 0; //to be init
   tcp->urg = 0; //imposed

   return 20;
}

struct tcp_pseudo {
   unsigned int saddr, daddr;
   unsigned char zero;
   unsigned char prot;
   unsigned short len;
   unsigned char tcp_packet[20];
};


struct icmp_packet {
unsigned char type;
unsigned char code;
unsigned short checksum;
unsigned short id;
unsigned short seq;
unsigned char data[1]; 
};

struct ip_datagram {
unsigned char ver_ihl;
unsigned char tos;
unsigned short len;
unsigned short id;
unsigned short flags_offs;
unsigned char ttl;
unsigned char proto;
unsigned short checksum;
unsigned int src;
unsigned int dst;
unsigned char payload[1];
};

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

void forge_eth( struct ethernet_frame * eth, unsigned char *dst, unsigned short type );
void printbuf ( unsigned char * b, int s);

int s; //Global socket
struct sockaddr_ll sll;

int arp_resolve(unsigned int ipaddr, unsigned char * mac){
int len,t;
unsigned char buffer[1000];
struct ethernet_frame * eth;
struct arp_packet * arp;
eth = (struct ethernet_frame *) buffer;
arp = (struct arp_packet * ) eth->payload;
forge_eth(eth,broadcast,0x0806);
arp->haddr = htons(1); arp->paddr = htons(0x0800);
arp->hlen = 6; arp->plen = 4; arp->op = htons(1);
for(int i=0; i<6; i++) arp->srcmac[i]=mymac[i];
for(int i=0; i<4; i++) arp->srcip[i]=myip[i];
for(int i=0; i<6; i++) arp->dstmac[i]=0;
arp->dstip = ipaddr;
printf("ARP Request: ");
for(int i=0; i<22;i++) buffer[14+28+i]=0;
printbuf(buffer,64);
for(int i=0; i<sizeof(struct sockaddr_ll); i++) ((char*)&sll)[i]=0;
sll.sll_family=AF_PACKET;
sll.sll_ifindex = if_nametoindex("eth0");
len = sizeof(struct sockaddr_ll);
t = sendto(s, buffer, 64, 0 ,(struct sockaddr *) &sll, len);
if ( t == -1) {perror("sendto Failed"); return 1;}
printf("ARP Request %d bytes sent\n",t);
for(int i=0; i<200; i++) {
	t = recvfrom(s, buffer, 1000, 0 ,(struct sockaddr *) &sll, &len);
 	if ( eth->type == htons(0x0806))
		if(arp->op == htons(2))
			if(!memcmp(arp->srcip,&ipaddr,4)) {
			printf("ARP response:");
			printbuf(buffer, t ) ;
			for(int j=0;j<6;j++) mac[j]=arp->srcmac[j];
			return 0; 
			}  
	}
	printf("No ARP response received\n");
	return -1;
}



unsigned short checksum ( void * b, int s)
{
unsigned short * p;
int i;
unsigned int tot=0;
p = (unsigned short *) b;
for (i=0; i<s/2; i++){
	tot +=ntohs(p[i]);
	if ( tot & 0x10000) tot = (tot&0xFFFF) + 1;	
}
if ( i*2 != s ){
	tot+=ntohs(p[i])&0xFF00;
	if ( tot & 0x10000) tot = (tot&0xFFFF) + 1;	
}
return  (0xFFFF-(unsigned short)tot);
}

int forge_icmp(struct icmp_packet * icmp){
int i;
icmp->type = 8;
icmp->code = 0;
icmp->checksum = 0;
icmp->id = 0x1234;
icmp->seq = 0;
for(i=0;i<32;i++) icmp->data[i]=i;
icmp->checksum = htons(checksum(icmp,40));
return 40;
}

void forge_ip(struct ip_datagram * ip, unsigned char* dst,  unsigned short payloadlen, unsigned char proto  )
{
ip->ver_ihl = 0x45;
ip->tos = 0;
ip->len = htons(payloadlen+20);
ip->id = 0xABCD;
ip->flags_offs = 0;
ip->ttl = 128;
ip->proto = proto;
ip->checksum = 0;
ip->src = *(unsigned int *)myip;
ip->dst = *(unsigned int *)dst;
ip->checksum = htons(checksum(ip,20));
}
void forge_eth( struct ethernet_frame * eth, unsigned char *dst, unsigned short type   )
{
for(int i=0;i<6;i++) eth->dst[i] = dst[i];
for(int i=0;i<6;i++) eth->src[i] = mymac[i];
eth->type = htons(type);
}

void printbuf ( unsigned char * b, int s)
{
int i;
for(i=0;i<s;i++){
	if (i%4==0)printf("\n%.3d: ",i);
	printf("%.2x(%.3d) ",b[i],b[i]);
	}
printf("\n");
}
/*

 struct sockaddr_ll {
               unsigned short sll_family;   // Always AF_PACKET 
               unsigned short sll_protocol; // Physical-layer protocol
               int            sll_ifindex;  // Interface number
               unsigned short sll_hatype;   // ARP hardware type
               unsigned char  sll_pkttype;  // Packet type 
               unsigned char  sll_halen;    // Length of address
               unsigned char  sll_addr[8];  // Physical-layer address
           };


*/
unsigned char rcvbuf[1500];
unsigned char buf[1500];
int main(){
int t,len;
unsigned char destip[4] = {88,80,187,84};
//unsigned char destip[4] = {147,162,2,100};
unsigned char destmac[6]; 

//## struct icmp_packet *icmp;
struct tcp_segment *tcp;
struct ip_datagram * ip;
struct ethernet_frame * eth;

eth = (struct ethernet_frame *) buf;
ip = (struct ip_datagram *) (eth->payload);
//## icmp = (struct icmp_packet *) (ip->payload);
tcp = (struct tcp_segment *) (ip->payload);

srand(time(NULL));
unsigned short sport = (unsigned short)(rand()%1000);
unsigned int seq = (unsigned short)(rand() % 1000);
//## len = forge_icmp(icmp);
len = forge_tcp(tcp, sport, seq);
//## forge_ip(ip,destip,len, 1); 
forge_ip(ip,destip,len, 6); 

//##
struct tcp_pseudo pseudo;

memcpy(pseudo.tcp_packet, tcp, 20);
pseudo.zero = 0;
pseudo.saddr = ip->src;
pseudo.daddr = ip->dst;
pseudo.prot = 6;
pseudo.len = htons(20);
tcp->checksum = htons(checksum((unsigned char*)&pseudo, 20+12));

s = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
if ( s == -1 ) { perror("Socket Failed"); return 1; }
//bzero(&sll,sizeof(struct sockaddr_ll));
for(int i=0; i<sizeof(struct sockaddr_ll); i++) ((char*)&sll)[i]=0;
sll.sll_family=AF_PACKET;
sll.sll_ifindex = if_nametoindex("eth0");
len = sizeof(struct sockaddr_ll);
printf("Resolve MAC:\n");
printf("Sending Ping Packet:\n");
if(((*(unsigned int*)myip)&(*(unsigned int*)netmask)) ==
   (*(unsigned int*)destip&(*(unsigned int*)netmask)) )
		{ if(arp_resolve(*(unsigned int*)destip,destmac)) return 1;}
else  
		{ if(arp_resolve(*(unsigned int*)gateway,destmac)) return 1;}

	forge_eth(eth,destmac,0x0800);
		
printbuf(buf, 14 + 20 + 40 );
t = sendto(s, buf, 14+20+40, 0 ,(struct sockaddr *) &sll, len);
if ( t == -1) {perror("sendto Failed"); return 1;}
printf("%d bytes sent\n",t);
while(1){
	t = recvfrom(s, buf, 1500, 0 ,(struct sockaddr *) &sll, &len);
	if ( t == -1) {perror("recvfrom Failed"); return 1;}
//##
   if(htons(eth->type)==0x0800) {
      if(ip->proto == 6) {
         if(tcp->sport == htons(80)){
            if(tcp->dport == htons(sport)) {
               if(tcp->ack == htonl(seq+1)) {
                  if(tcp->flags = 18) {
                     printf("Received TCP Response: \n");
                     printbuf(buf, 14);
                     printbuf(buf+14, t-14);
                     break;
                  }
               }
            }
         }
      }
   }
}

} 
