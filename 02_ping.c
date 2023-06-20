/*
// ETHERNET FRAME STRUCTURE
0                        6                        12        14
+------------------------+------------------------+---------+
|   Destination MAC      |    Source MAC          |  Type   |
+------------------------+------------------------+---------+
|                                                           |
|                  Payload (varies in size)                 |
|                                                           |
+-----------------------------------------------------------+
|   Frame Check Sequence (FCS) (4 bytes, optional)          |
+-----------------------------------------------------------+
// IP DATAGRAM
0       4       8           14  16                              32
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|Version|  IHL  |    DSCP   |ECN|          Total Length         |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|         Identification        |Flags|     Fragment Offset     |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  Time to Live |    Protocol   |         Header Checksum       |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                           Source IP                           |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                        Destination IP                         |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
|                            Payload                            |
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// TCP SEGMENT 
0           8           16                                  32
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|         Source Port           |       Destination Port        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                          Sequence Number                      |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                      Acknowledgment Number                    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| Data  |Reserved | Control |            Window Size            |
| Offset|         |  Flags  |                                   |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|           Checksum            |         Urgent Pointer        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
|                            Payload                            |
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/

/*
This program demonstrates network management functionalities using raw sockets in C.
It performs a basic ICMP (ping) operation to send an ICMP echo request packet to a destination IP address and receive the corresponding ICMP echo response.

The program follows these steps:
1. Resolves the MAC address of the destination IP using the Address Resolution Protocol (ARP).
2. Crafts an ICMP echo request packet.
3. Creates a raw socket and sends the ICMP packet using the socket.
4. Waits for a response on the socket.
5. Checks if the received packet is an ICMP echo response.
6. Prints the received packet.

Note: This program assumes the network interface name is "eth0" and uses specific IP, MAC, and gateway addresses. 
Modify them as per your network configuration.
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

// MAC addresses and IP addresses used in the program
unsigned char broadcast[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
unsigned char mymac[6] = {0xf2, 0x3c, 0x91, 0xdb, 0xc2, 0x98};
unsigned char myip[4] = {88, 80, 187, 84};
unsigned char netmask[4] = {255, 255, 255, 0};
unsigned char gateway[4] = {88, 80, 187, 1};


// ICMP packet structure
/*
The ICMP packet is a protocol used for diagnostic and error reporting purposes in IP networks. 
It allows network devices to send control messages to other devices or report errors encountered during packet transmission.

0               8               16                              32
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|      Type     |     Code      |           Checksum            |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                           Identifier                          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                             Sequence                          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
|                         Data (optional)                       |
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

    Type (8 bits): Specifies the type of ICMP message. (e.g., 0=echo reply, 3=destination unreachable, 5=redirect message, 8=echo request/ping, 11=time exceeded)
    Code (8 bits): Provides additional information about the ICMP message.
    Checksum (16 bits): A checksum value calculated over the entire ICMP packet to ensure data integrity.
    Identifier (16 bits): An identifier used to match echo requests and replies.
    Sequence (16 bits): A sequence number used to match echo requests and replies.
    Data (optional): Additional data included in the ICMP packet, such as timestamps or error information.
*/

struct icmp_packet {
    unsigned char type;
    unsigned char code;
    unsigned short checksum;
    unsigned short id;
    unsigned short seq;
    unsigned char data[1];
};


// IP datagram structure
/*
The IP datagram serves as the fundamental unit of information exchange in IP networks. 
It encapsulates higher-level protocols, such as ICMP, TCP, or UDP, and facilitates the routing and delivery of packets across interconnected networks.

0       4       8           14  16                              32
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|Version|  IHL  |    DSCP   |ECN|          Total Length         |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|         Identification        |Flags|     Fragment Offset     |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  Time to Live |    Protocol   |         Header Checksum       |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                           Source IP                           |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                        Destination IP                         |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
|                            Payload                            |
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

    Version (4 bits): Indicates the IP version being used (e.g., IPv4 or IPv6).
    IHL (4 bits): Internet Header Length, representing the length of the IP header in 32-bit words.
    DSCP (6 bits): Differentiated Services Code Point, used for quality of service (QoS) and traffic prioritization.
    ECN (2 bits): Explicit Congestion Notification, used for congestion control.
    Total Length (16 bits): Total length of the IP datagram (header + payload).
    Identification (16 bits): Uniquely identifies the IP datagram among a set of fragmented datagrams.
    Flags (3 bits): Control flags for fragmentation and reassembly.
    Fragment Offset (13 bits): Indicates the position of the current fragment in the original datagram.
    Time to Live (8 bits): Limits the lifespan of the datagram to prevent indefinite looping.
    Protocol (8 bits): Specifies the protocol encapsulated in the IP payload (e.g., 1=ICMP, 6=TCP, 17=UDP, 41=IPv6).
    Header Checksum (16 bits): A checksum value calculated over the IP header to ensure data integrity.
    Source IP (32 bits): The IP address of the sender.
    Destination IP (32 bits): The IP address of the intended recipient.
    Payload: The data being transmitted in the IP datagram.
*/
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


// Ethernet frame structure
/*
The Ethernet frame is the basic unit of data transmission in Ethernet networks.
It allows for reliable and efficient communication within Ethernet networks by encapsulating and delivering data to the intended recipients based on MAC addresses.

0                        6                        12        14
+------------------------+------------------------+---------+
|   Destination MAC      |    Source MAC          |  Type   |
+------------------------+------------------------+---------+
|                                                           |
|                  Payload (varies in size)                 |
|                                                           |
+-----------------------------------------------------------+
|   Frame Check Sequence (FCS) (4 bytes, optional)          |
+-----------------------------------------------------------+

    Destination MAC (6 bytes): Represents the MAC address of the destination device or broadcast address.
    Source MAC (6 bytes): Represents the MAC address of the sending device.
    Type (2 bytes): Specifies the protocol type of the encapsulated payload (e.g., 0x0800 for IPv4, 0x0806 for ARP, and 0x86DD for IPv6.).
*/
struct ethernet_frame {
    unsigned char dst[6];
    unsigned char src[6];
    unsigned short type;
    unsigned char payload[1];
};


// ARP packet structure
/*
The ARP packet is used to resolve an IP address to its corresponding MAC address in a local network.

0                 2                  4                  5                 6       8
+-----------------+------------------+------------------+-----------------+-------+
|  Hardware Type  |  Protocol Type   |  Hardware Length | Protocol Length |  OP   |
+-----------------+------------------+------------------+-----------------+-------+
|                          Sender MAC Address (6 bytes)                   |
+-----------------+------------------+------------------+-----------------+
|   Sender IP Address (4 bytes)      |
+-----------------+------------------+------------------+-----------------+
|                       Target MAC Address (6 bytes)                      |
+-----------------+------------------+------------------+-----------------+
|   Target IP Address (4 bytes)      |
+-----------------+------------------+

    Hardware Type (2 bytes): Specifies the type of hardware interface, such as Ethernet (0x0001) or Token Ring (0x0006).
    Protocol Type (2 bytes): Indicates the protocol type of the addresses, typically IPv4 (0x0800) or IPv6 (0x86DD).
    Hardware Length (1 byte): Indicates the length (in bytes) of the hardware address, such as MAC address (6 bytes).
    Protocol Length (1 byte): Specifies the length (in bytes) of the protocol address, such as IPv4 address (4 bytes).
    OP (Operation) (2 bytes): Specifies the operation being performed, such as ARP Request (1) or ARP Reply (2).
*/
struct arp_packet {
    unsigned short haddr;
    unsigned short paddr;
    unsigned char hlen;
    unsigned char plen;
    unsigned short op;
    unsigned char srcmac[6];
    unsigned char srcip[4];
    unsigned char dstmac[6];
    unsigned int dstip;
};

// TCP segment structure
/*
The TCP segment is a unit of data exchange in the TCP/IP protocol suite. It represents a portion of a TCP connection, carrying data between the source and destination.

0           8           16                                  32
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|         Source Port           |       Destination Port        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                          Sequence Number                      |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                      Acknowledgment Number                    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| Data  |Reserved | Control |            Window Size           |
| Offset|         |  Flags  |                                   |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|           Checksum            |         Urgent Pointer         |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
|                            Payload                            |
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

    Source Port (16 bits): The port number of the sender.
    Destination Port (16 bits): The port number of the intended recipient.
    Sequence Number (32 bits): A unique number identifying each byte of data being sent.
    Acknowledgment Number (32 bits): The next expected sequence number from the other side.
    Data Offset (4 bits): The length of the TCP header in 32-bit words.
    Reserved (3 bits): Reserved for future use.
    Control Flags (9 bits): Various control flags for TCP operations (e.g., SYN, ACK, FIN).
    Window Size (16 bits): The number of bytes the receiver can accept without acknowledgment.
    Checksum (16 bits): A checksum value calculated over the TCP header and payload to ensure data integrity.
    Urgent Pointer (16 bits): Points to the last byte of urgent data.
    Payload: The actual data being transmitted in the TCP segment.
*/

struct tcp_segment {
    unsigned short s_port;      // Source Port
    unsigned short d_port;      // Destination Port
    unsigned int seq;           // Sequence Number
    unsigned int ack;           // Acknowledgment Number
    unsigned char d_offs_res;   // Data Offset (4 bits) + Reserved (3 bits)
    unsigned char flags;        // Control Flags (9 bits)
    unsigned short window;      // Window Size
    unsigned short checksum;    // Checksum
    unsigned short urgp;        // Urgent Pointer
    unsigned char payload[TCP_MSS];  // Payload
};


// Function declarations
void forge_eth(struct ethernet_frame *eth, unsigned char *dst, unsigned short type);
void printbuf(unsigned char *b, int s);
unsigned short checksum(void *b, int s);
int forge_icmp(struct icmp_packet *icmp);
void forge_ip(struct ip_datagram *ip, unsigned char *dst, unsigned short payloadlen, unsigned char proto);
int arp_resolve(unsigned int ipaddr, unsigned char *mac);

int s; // Global socket
struct sockaddr_ll sll;

/*
Resolves the MAC address corresponding to the given IP address using Address Resolution Protocol (ARP).

Parameters:
- ipaddr: The IP address to resolve.
- mac: Pointer to an array to store the resolved MAC address.

Returns:
- 0 if MAC address resolution is successful.
- -1 if no ARP response is received.
- 1 if an error occurs
*/
int arp_resolve(unsigned int ipaddr, unsigned char *mac) {
    int len, t;
    unsigned char buffer[1000];
    struct ethernet_frame *eth;
    struct arp_packet *arp;
    eth = (struct ethernet_frame *)buffer;
    arp = (struct arp_packet *)eth->payload;

    forge_eth(eth, broadcast, 0x0806);
    arp->haddr = htons(1);
    arp->paddr = htons(0x0800);
    arp->hlen = 6;
    arp->plen = 4;
    arp->op = htons(1);
    for (int i = 0; i < 6; i++)
        arp->srcmac[i] = mymac[i];
    for (int i = 0; i < 4; i++)
        arp->srcip[i] = myip[i];
    for (int i = 0; i < 6; i++)
        arp->dstmac[i] = 0;
    arp->dstip = ipaddr;

    printf("ARP Request:");
    for (int i = 0; i < 22; i++)
        buffer[14 + 28 + i] = 0;
    printbuf(buffer, 64);

    for (int i = 0; i < sizeof(struct sockaddr_ll); i++)
        ((char *)&sll)[i] = 0;
    sll.sll_family = AF_PACKET;
    sll.sll_ifindex = if_nametoindex("eth0");
    len = sizeof(struct sockaddr_ll);
    t = sendto(s, buffer, 64, 0, (struct sockaddr *)&sll, len);
    if (t == -1) {
        perror("sendto Failed");
        return 1;
    }
    printf("ARP Request %d bytes sent\n", t);

    for (int i = 0; i < 200; i++) {
        t = recvfrom(s, buffer, 1000, 0, (struct sockaddr *)&sll, &len);
        if (t == -1) {
            perror("recvfrom Failed");
            return 1;
        }
        if (eth->type == htons(0x0806))
            if (arp->op == htons(2))
                if (*(unsigned int *)arp->srcip == ipaddr) {
                    printf("ARP Response:");
                    printbuf(buffer, t);
                    for (int j = 0; j < 6; j++)
                        mac[j] = arp->srcmac[j];
                    return 0;
                }
    }

    printf("No ARP response received\n");
    return -1;
}

/*
Calculates the checksum for a given buffer.

Parameters:
- b: Pointer to the buffer.
- s: Size of the buffer.

Returns:
- The calculated checksum.
*/
unsigned short checksum(void *b, int s) {
    unsigned short *p;
    int i;
    unsigned int tot = 0;
    p = (unsigned short *)b;
    for (i = 0; i < s / 2; i++) {
        tot += ntohs(p[i]);
        if (tot & 0x10000)
            tot = (tot & 0xFFFF) + 1;
    }
    if (i * 2 != s) {
        tot += ntohs(p[i]) & 0xFF00;
        if (tot & 0x10000)
            tot = (tot & 0xFFFF) + 1;
    }
    return (0xFFFF - (unsigned short)tot);
}

/*
Crafts an IP datagram.

Parameters:
- ip: Pointer to the IP datagram structure.
- dst: Destination IP address.
- payloadlen: Length of the payload.
- proto: IP protocol number.

Returns: None
*/
void forge_ip(struct ip_datagram *ip, unsigned char *dst, unsigned short payloadlen, unsigned char proto) {
    ip->ver_ihl = 0x45; // ip_version = IPv4 and Internet_header_length = 5 words = 20 byte 
    ip->tos = 0; // Type Of Service (instead of DSCP + ECN), specifies priority and latence. 
    ip->len = htons(payloadlen + 20); // Ip header fixed size = 20 bytes
    ip->id = 0;
    ip->flags_offs = 0;
    ip->ttl = 64;
    ip->proto = proto;
    ip->checksum = 0;
    ip->src = *(unsigned int *)myip;
    ip->dst = *(unsigned int *)dst;
    ip->checksum = htons(checksum(ip, 20)); // calculates the checksum value based on the contents of the IP header.
}

/*
Crafts an ICMP echo request packet.

Parameters:
- icmp: Pointer to the ICMP packet structure.

Returns:
- 0 if successful.
*/
int forge_icmp(struct icmp_packet *icmp) {
    icmp->type = 8; // 8 = echo request/ping
    icmp->code = 0; // 0 = general request
    icmp->checksum = 0; 
    icmp->id = htons(0x666);
    icmp->seq = htons(1);
    memset(icmp->data, 0, 56); // fills the data portion of the ICMP packet with zeros
    icmp->checksum = htons(checksum(icmp, 64)); // calculates the checksum for the ICMP packet
    return 0;
}

/*
Crafts an Ethernet frame.

Parameters:
- eth: Pointer to the Ethernet frame structure.
- dst: Destination MAC address.
- type: Ethernet frame type.

Returns: None
*/
void forge_eth(struct ethernet_frame *eth, unsigned char *dst, unsigned short type) {
    memcpy(eth->dst, dst, 6);
    memcpy(eth->src, mymac, 6);
    eth->type = htons(type);
}

/*
Prints the buffer in hexadecimal format.

Parameters:
- b: Pointer to the buffer.
- s: Size of the buffer.

Returns: None
*/
void printbuf(unsigned char *b, int s) {
    int i;
    for (i = 0; i < s; i++) {
        printf("%02x ", b[i]);
        if (i % 16 == 15)
            printf("\n");
    }
    printf("\n");
}

int main() {
    unsigned char mac[6];
    unsigned char packet[1000];
    struct ethernet_frame *eth;
    struct ip_datagram *ip;
    struct icmp_packet *icmp;
    struct sockaddr_ll sll;
    int len, t;

    // Create a raw socket
    s = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (s == -1) {
        perror("socket Failed");
        return 1;
    }

    // Set socket options
    if (setsockopt(s, SOL_SOCKET, SO_BINDTODEVICE, "eth0", strlen("eth0")) == -1) {
        perror("setsockopt Failed");
        return 1;
    }

    eth = (struct ethernet_frame *)packet;
    ip = (struct ip_datagram *)eth->payload;
    icmp = (struct icmp_packet *)ip->payload;

    // Resolve the MAC address of the destination IP using ARP
    if (arp_resolve(*(unsigned int *)gateway, mac) == -1) {
        printf("Unable to resolve MAC address\n");
        return 1;
    }

    // Craft the Ethernet frame
    forge_eth(eth, mac, 0x0800); // 0x0800 = IPv4 type

    // Craft the IP datagram
    forge_ip(ip, gateway, 64, 1);

    // Craft the ICMP echo request packet
    forge_icmp(icmp);

    printf("Sending ICMP packet:\n");
    printbuf(packet, 14 + 20 + 8); // Ethernet frame (14 bytes), IP datagram (20 bytes), and ICMP packet (8 bytes)

    // Send the ICMP packet using the raw socket
    len = sizeof(struct sockaddr_ll);
    memset(&sll, 0, len); // clear the sll structure from eventual leftovers
    sll.sll_family = AF_PACKET;
    sll.sll_ifindex = if_nametoindex("eth0");
    t = sendto(s, packet, 14 + 20 + 8, 0, (struct sockaddr *)&sll, len); // sends the ICMP packet using raw socket, t = # of bytes sent
    if (t == -1) {
        perror("sendto Failed");
        return 1;
    }
    printf("ICMP packet sent\n");

    // Wait for the response on the socket
    while (1) { 
        t = recvfrom(s, packet, 1000, 0, (struct sockaddr *)&sll, &len); // receives a packet of max size 1000 bytes, stores the packet in the 'packet' buffer and the source address info in the 'sll' structure
        if (t == -1) {
            perror("recvfrom Failed");
            return 1;
        }
        printf("Received ICMP packet:\n");
        printbuf(packet, t); // t = actual size of the received packet stored in 'packet' buffer
        break; // the ICMP packet has been received and processed
    }

    return 0;
}
