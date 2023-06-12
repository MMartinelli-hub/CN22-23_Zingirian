/*
 * This program is a simple network sniffer that captures packets on the specified interface (eth0).
 * It uses raw sockets to capture all packets, including Ethernet, IP, TCP, UDP, etc.
 * The received packets are then printed as hexadecimal values.
 */

#include <sys/types.h>          /* See NOTES */
#include <arpa/inet.h>
#include <strings.h>
#include <sys/socket.h>
#include <linux/if_packet.h>
#include <net/ethernet.h> /* the L2 protocols */
#include <net/if.h>
#include <stdio.h>

struct sockaddr_ll sll;
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

int main() {
    int s, t, len;

    // Create a raw socket to capture all packets
    s = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (s == -1) {
        perror("Socket Failed");
        return 1;
    }

    // Initialize the sockaddr_ll structure
    bzero(&sll, sizeof(struct sockaddr_ll));
    sll.sll_family = AF_PACKET;
    sll.sll_ifindex = if_nametoindex("eth0");

    len = sizeof(struct sockaddr_ll);

    // Receive packets and print their hexadecimal values
    t = recvfrom(s, rcvbuf, 1500, 0, (struct sockaddr *)&sll, &len);
    for (int i = 0; i < t; i++) {
        printf("%.2x (%.3d) ", rcvbuf[i], rcvbuf[i]);
    }

    return 0;
}