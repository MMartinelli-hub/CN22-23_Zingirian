#INCLUDE <stdio.h>
#INCLUDE <sys/socket.h>
#INCLUDE <sys/type.h>
#INCLUDE <net/if.h>
#INCLUDE <strings.h>

struct ethernet_frame{
unsigned char dst[6];
unsigned char src[6];
unsigned short type;
};

struct arp_datagram{
unsigned short has;
unsigned short pas;
unsigned char halen;
unsigned char prlen;
unsigned short opcode;
unsigned char src_eth_addr[6];
unsigned int src_ip;
unsigned char dst_eth_addr[6];
unsigned int dst_ip;
};

void forge_eth(unsigned chrar







unsigned char myip[4]={};
unsigned char mymac[6]={};

int main(){








}
