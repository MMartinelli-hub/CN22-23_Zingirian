/*
   Author: Marco Martinelli
   Implementation Date: 15/06/2023
   Time Took: 20 min

# IDEA #
- We set the dst ip to something from which we can except various responses -> bitsei.it
         89.90.142.15

- For all ethernet packets
   > IPv4 packets: 0x0800
   > ARP packets: 0x0806

- For all ip packets
   > TCP: 6
   > UDP: 17
   > ICMP: 1

- We modify the main so to intercept the codes above
- We define a counter for each of these
- We loop the recvfrom 1000 times so to receive 1000 packets from the network (RAW SOCK, read blabla)
- We do fancy Math and compute the statistics required

   All the modifications to the code can be found by searching for '##'

# OUTPUT #
-------- GENERAL STATISTICS --------
Total packets received: 1000
IP packets received: 854 - 85.40%
ARP packets received: 115 - 11.50%
Neither packets received: 31 - 3.10%

-------- IP STATISTICS --------
Total IP packets received: 854
ICMP packets received: 0 - 0.00%
TCP packets received: 848 - 99.30%
UDP packets received: 6 - 0.70%
Other packets received: 0 - 0.00%

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
//unsigned char destip[4] = {88,80,187,124};
//unsigned char destip[4] = {147,162,2,100};
unsigned char destip[4] = {89,90,142,15};
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

//## Counters for all ethernet packets
unsigned int eth_cont = 0;
unsigned int ip_cont = 0;
unsigned int arp_cont = 0;
unsigned int neither_cont = 0;

//## Counters for ip packets
unsigned int tcp_cont = 0;
unsigned int udp_cont = 0;
unsigned int icmp_cont = 0;
unsigned int other_cont = 0;

//##
for(int i=0; i<1000; i++){
	t = recvfrom(s, buf, 1500, 0 ,(struct sockaddr *) &sll, &len);
	if ( t == -1) {perror("recvfrom Failed"); return 1;}
	if(htons(eth->type)==0x0800) { //IP response
      ip_cont++;
      if(ip->proto == 1) { //ICMP segment
         icmp_cont++;
      }
      else if(ip->proto == 6) { //TCP segment
         tcp_cont++;
      } else if(ip->proto == 17) { //UDP segment
         udp_cont++;
      } else {
         other_cont++;
      }
   } else if(htons(eth->type) == 0x0806) { //ARP response
      arp_cont++;

   } else { //Neither response 
      neither_cont++;

   }
}


printf("\n\n-------- GENERAL STATISTICS --------\n");
eth_cont = ip_cont+arp_cont+neither_cont;
printf("Total packets received: %u\n", eth_cont);
printf("IP packets received: %u - %.2f\%\n", ip_cont, (float)ip_cont*100/eth_cont);
printf("ARP packets received: %u - %.2f\%\n", arp_cont, (float)arp_cont*100/eth_cont);
printf("Neither packets received: %u - %.2f\%\n", neither_cont, (float)neither_cont*100/eth_cont);

printf("\n\n-------- IP STATISTICS --------\n");
printf("Total IP packets received: %u\n", ip_cont);
printf("ICMP packets received: %u - %.2f\%\n", icmp_cont, (float)icmp_cont*100/ip_cont);
printf("TCP packets received: %u - %.2f\%\n", tcp_cont, (float)tcp_cont*100/ip_cont);
printf("UDP packets received: %u - %.2f\%\n", udp_cont, (float)udp_cont*100/ip_cont);
printf("Other packets received: %u - %.2f\%\n", other_cont, (float)other_cont*100/ip_cont);


} 
