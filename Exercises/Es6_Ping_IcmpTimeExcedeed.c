/*
   Author: Marco Martinelli
   Implementation date: 15/06/2023
   Time took: 20 min

IDEA:
- We launch tceroute to 147.162.2.100 traceroute from terminal 
on the dest ip 147.162.2.100 to see the num of hops

# Traceroute printout #
(147.162.2.100), 30 hops max, 60 byte packets
 1  89-40-142-1.virtualsolution.net (89.40.142.1)  1.027 ms  1.155 ms  2.197 ms
  2  10.1.2.6 (10.1.2.6)  2.188 ms  2.245 ms  2.591 ms
   3  10.0.3.50 (10.0.3.50)  0.254 ms  0.278 ms  0.257 ms
    4  10.0.0.18 (10.0.0.18)  1.952 ms  1.931 ms  1.901 ms
     5  garr.mix-it.net (217.29.66.39)  1.841 ms  1.810 ms  1.760 ms
      6  re1-mi02-rs1-bo01.bo01.garr.net (185.191.180.56)  9.624 ms  9.592 ms re1-mi02-rs1-mi01.mi01.garr.net (185.191.180.159)  1.574 ms
       7  rs1-mi01-rs1-pd01.pd01.garr.net (185.191.181.10)  4.375 ms  4.248 ms  4.362 ms
        8  185.191.181.13 (185.191.181.13)  7.653 ms  7.623 ms rs1-pd02-rl1-pd01.pd01.garr.net (185.191.181.14)  11.365 ms
         9  rt-pd1-ru-unipd.pd1.garr.net (193.206.132.222)  11.206 ms  7.578 ms  7.555 ms
         10  147.162.28.21 (147.162.28.21)  9.456 ms  9.435 ms  4.738 ms
         11  147.162.238.18 (147.162.238.18)  8.732 ms  12.447 ms  12.430 ms
         12  * * *
         13  147.162.38.225 (147.162.38.225)  9.198 ms  12.840 ms  12.697 ms
         14  * * *
         15  * * *
         16  * * *
         17  * * *
         18  * * *
         19  * * *
         20  * * *
         21  * * *
         22  * * *
         23  * * *
         24  * * *
         25  * * *
         26  * * *
         27  * * *
         28  * * *
         29  * * *
         30  * * *
         )))))))))))))))

   - We set the ip ttl to a number (=8) < num of hops = 13
   - We modify the main to intercept the icmp response
   - On the intercept, if type == 11, we print the src ip 
   - By the icmp code we can also understand if we received by a gateway (==0)
   so we can be sure we didn't reach the destination

   All the modifications can be found searching for '##'

FINAL OUTPUT
   Time to live excedeed in transit
   Response may be received from a gateway
   Generating IP address: 185.191.181.14 
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

unsigned char broadcast[6]={0xFF,0xFF,0xFF,0xFF,0xFF,0xFF};
unsigned char mymac[6] = { 0xbe,0x63,0xb2,0xfb,0x8d,0x33} ; 
unsigned char myip[4] = { 89,40,142,15 }; 
unsigned char netmask[4]={255,255,255,0};
unsigned char gateway[4]={89,40,142,1};
 
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
//## ip->ttl = 128;
ip->ttl = 8;
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
//unsigned char destip[4] = {88,80,187,124};
unsigned char destip[4] = {147,162,2,100};
unsigned char destmac[6]; 

struct icmp_packet *icmp;
struct ip_datagram * ip;
struct ethernet_frame * eth;

eth = (struct ethernet_frame *) buf;
ip = (struct ip_datagram *) (eth->payload);
icmp = (struct icmp_packet *) (ip->payload);

len = forge_icmp(icmp);
forge_ip(ip,destip,len, 1); 

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
	if(htons(eth->type)==0x0800) 
		if(ip->proto == 1 ){
	   	if(icmp->type == 0 ){
				printf("Received Ping Response:\n");
				printbuf(buf,t);
				break;
			} 
         //##
         if(icmp->type == 11 ){
            if(icmp->code == 0) {
               printf("Time to live excedeed in transit\n");
               printf("Response may be received from a gateway\n");
            }
            if(icmp->code == 1) {
               printf("Fragment reassembly time exceeded\n");
               printf("Response may be receivedhas from a host\n");
            }
				//printbuf(buf,t);
            unsigned char* octets = (unsigned char*) &ip->src;
            printf("Generating IP address: %hhu.%hhu.%hhu.%hhu\n", octets[0], octets[1], octets[2], octets[3]);
            break;
			} 
      }
	}
} 
