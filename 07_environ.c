#include <arpa/inet.h>
#include <errno.h>
#include <stdio.h>
#include <signal.h>
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

/*
 * This program implements an ARP resolver.
 *
 * It resolves the MAC address for a given IP address by sending an ARP request and waiting for the ARP response. 
 * It maintains an ARP cache to store resolved IP-MAC mappings for faster lookup.
 *
 * The program uses raw socket to send and receive Ethernet frames.
 */

#define CACHE_SZ 100 // set the cache size at 100

// MAC addresses and IP addresses used in the program
unsigned char broadcast[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
unsigned char mymac[6] = {0xf2, 0x3c, 0x91, 0xDB, 0xC2, 0x98};
unsigned char myip[4] = {88, 80, 187, 84};
unsigned char netmask[4] = {255, 255, 255, 0};
unsigned char gateway[4] = {88, 80, 187, 1};


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

// ARP cache entry structure
struct arp_cache {
    unsigned int ip;
    unsigned char mac[6];
    unsigned int t_created;
    unsigned char occupied;
} cache[CACHE_SZ]; // ARP cache of size 100


// Function declarations
void forge_eth(struct ethernet_frame *eth, unsigned char *dst, unsigned short type);

#define MAXFRAME 10000    // Maximum frame size for receiving packets
#define TIMER_USECS 100000   // Timer interval in microseconds

int pkts = 0;   // Counter for the number of packets received

struct sigaction action_io, action_timer;   // Signal action structures for I/O and timer signals
sigset_t mymask;   // Signal mask for blocking/unblocking signals
unsigned char l2buffer[MAXFRAME];   // Buffer for storing the received packets
struct sockaddr_ll;   // Placeholder for the link-layer socket address structure
struct pollfd fds[1];   // File descriptor structure for polling I/O events
int fdfl;   // File descriptor flags
long long int tick = 0;   // Timer tick count
int unique_s;   // Unique socket identifier
int fl;   // Flag for tracking overlapping signals
struct sockaddr_ll sll;   // Link-layer socket address structure


/*
Prints the buffer content in hexadecimal and decimal format

Prints the content of a buffer as hexadecimal values.

Parameters:
- b: Pointer to the buffer
- size: Size of the buffer

Returns: None
*/
int printbuf(void *b, int size)
{
    int i;
    unsigned char *c = (unsigned char *)b;
    for (i = 0; i < size; i++)
        printf("%.2x(%.3d) ", c[i], c[i]);
    printf("\n");
}

/*
Function to resolve the MAC address for a given IP address.
It sends an ARP request and waits for the ARP response.
If the IP-MAC mapping is found in the cache, it returns the MAC address directly.
Returns 0 on success, -1 on failure, and updates the 'mac' parameter with the resolved MAC address.
*/
int arp_resolve(unsigned int ipaddr, unsigned char *mac) {
    int len, t;
    unsigned char buffer[1000];
    struct ethernet_frame *eth;
    struct arp_packet *arp;
    
    // Check if the MAC address for the IP address is already present in the cache
    for (int i = 0; i < CACHE_SZ; i++) {
        if (cache[i].occupied) {
            if (cache[i].ip == ipaddr) {
                for (int k = 0; k < 6; k++)
                    mac[k] = cache[i].mac[k];
                return 0;
            }
        }
    }

    // Prepare the ARP request packet
    eth = (struct ethernet_frame *)buffer;
    arp = (struct arp_packet *)eth->payload;

    forge_eth(eth, broadcast, 0x0806);  // Set the destination MAC address and Ethernet type (ARP)
    arp->haddr = htons(1);  // Hardware type: Ethernet
    arp->paddr = htons(0x0800);  // Protocol type: IPv4
    arp->hlen = 6;  // Hardware address length (MAC address length)
    arp->plen = 4;  // Protocol address length (IPv4 address length)
    arp->op = htons(1);  // ARP operation: Request
    for (int i = 0; i < 6; i++)
        arp->srcmac[i] = mymac[i];  // Set the source MAC address
    for (int i = 0; i < 4; i++)
        arp->srcip[i] = myip[i];  // Set the source IP address
    for (int i = 0; i < 6; i++)
        arp->dstmac[i] = 0;  // Initialize the destination MAC address
    arp->dstip = ipaddr;  // Set the destination IP address

    printf("ARP Request\n");

    // Prepare the link-layer socket address structure
    for (int i = 0; i < sizeof(struct sockaddr_ll); i++)
        ((char *)&sll)[i] = 0;
    sll.sll_family = AF_PACKET;
    sll.sll_ifindex = if_nametoindex("eth0");

    len = sizeof(struct sockaddr_ll);
    
    // Send the ARP request packet
    t = sendto(unique_s, buffer, 64, 0, (struct sockaddr *)&sll, len);
    if (t == -1) {
        perror("sendto Failed");
        return 1;
    }
    
    unsigned int time = tick;
    
    // Wait for the ARP response or a timeout
    while (pause()) {
        // Check if the MAC address for the IP address is already present in the cache
        for (int i = 0; i < CACHE_SZ; i++) {
            if (cache[i].occupied) {
                if (cache[i].ip == ipaddr) {
                    for (int k = 0; k < 6; k++)
                        mac[k] = cache[i].mac[k];
                    return 0;
                }
            }
        }
        
        // Check if the timeout has occurred
        if (tick - time >= 3)
            return -1;
    }
}

/*
Function to forge Ethernet frame.
Sets the destination MAC address, source MAC address, and frame type.
*/
void forge_eth(struct ethernet_frame *eth, unsigned char *dst, unsigned short type)
{
    for (int i = 0; i < 6; i++)
        eth->dst[i] = dst[i];
    for (int i = 0; i < 6; i++)
        eth->src[i] = mymac[i];
    eth->type = htons(type);
}


/*
Timer Signal Handler

Handles the timer signal and performs cache maintenance tasks.

Parameters:
- number: Signal number

Returns: None
 */
void mytimer(int number) {
    int i;
    
    if (-1 == sigprocmask(SIG_BLOCK, &mymask, NULL)) {
        perror("sigprocmask");
        return;
    }
    
    fl++;   // Increment the flag to track overlapping signals
    tick++;   // Increment the timer tick count
    
    if (tick % (1000000 / TIMER_USECS) == 0) {
        printf("Mytimer Called: pkts = %d\n", pkts);
        pkts = 0;   // Reset the packet counter
    }
    
    if (fl > 1) {
        printf("Overlap Timer\n");
    }
    
    fl--;
    
    if (-1 == sigprocmask(SIG_UNBLOCK, &mymask, NULL)) {
        perror("sigprocmask");
        return;
    }
    
    // Iterate through the ARP cache and check the expiration time of each entry
    for (i = 0; i < CACHE_SZ; i++) {
        if (cache[i].occupied) {
            // If the cache entry has exceeded the expiration time (300 ticks),
            // mark it as unoccupied
            if (tick - cache[i].t_created >= 300) {
                cache[i].occupied = 0;
            }
        }
    }
}


/*
I/O Signal Handler

Handles the I/O signal and processes incoming packets.

Parameters:
- number: Signal number

Returns: None
 */
void myio(int number)
{
    int len, size;
    struct ethernet_frame *eth = (struct ethernet_frame *)l2buffer;   // Pointer to the Ethernet frame structure
    struct arp_packet *arp = (struct arp_packet *)eth->payload;   // Pointer to the ARP packet structure

    if (-1 == sigprocmask(SIG_BLOCK, &mymask, NULL)) {   // Block the specified signals using the signal mask
        perror("sigprocmask");
        return;
    }
    fl++;   // Increment the flag value to track overlapping calls to myio()

    if (fl > 1) {
        printf("Overlap (%d) in myio\n", fl);
    }

    if (poll(fds, 1, 0) == -1) {   // Poll for events on the file descriptor
        perror("Poll failed");
        return;
    }

    if (fds[0].revents & POLLIN) {   // Check if there is data to read from the file descriptor
        len = sizeof(struct sockaddr_ll);

        while (0 <= (size = recvfrom(unique_s, l2buffer, MAXFRAME, 0, (struct sockaddr *)&sll, &len))) {
            pkts++;   // Increment the packet counter

            if (eth->type == htons(0x0806)) {   // Check if the Ethernet frame type is ARP (0x0806)
                if (arp->op == htons(2)) {   // Check if the ARP operation is a reply (2)
                    /*
                    The received packet is an ARP response.
                    Handle the ARP response by extracting the sender's MAC and IP addresses and updating the ARP cache.
                    */

                    for (int i = 0; i < CACHE_SZ; i++) {
                        if (!cache[i].occupied) {
                            cache[i].occupied = 1;
                            cache[i].t_created = tick;
                            memcpy(cache[i].mac, arp->srcmac, 6);   // Copy the sender's MAC address to the cache entry
                            memcpy(&cache[i].ip, arp->srcip, 4);   // Copy the sender's IP address to the cache entry
                        }
                    }
                }
            }
        }

        if (errno != EAGAIN) {
            perror("Packet recvfrom Error\n");
        }
    }

    fds[0].events = POLLIN | POLLOUT;   // Set the events to monitor for the file descriptor
    fds[0].revents = 0;   // Clear the events that occurred on the file descriptor

    if (fl > 1) {
        printf("Overlap (%d) in myio\n", fl);
    }

    fl--;   // Decrement the flag value to indicate the completion of the myio() function

    if (-1 == sigprocmask(SIG_UNBLOCK, &mymask, NULL)) {   // Unblock the signals using the signal mask
        perror("sigprocmask");
        return;
    }
}



int main(int argc, char **argv)
{
    unsigned char target_ip[4] = {88, 80, 187, 1};   // Target IP address to resolve
    unsigned char target_mac[6];   // Target MAC address to be resolved

    fl = 0;   // Initialize the 'fl' flag

    struct itimerval myt;   // Structure for setting timer intervals
    action_io.sa_handler = myio;   // Set the I/O signal handler function
    action_timer.sa_handler = mytimer;   // Set the timer signal handler function

    sigaction(SIGIO, &action_io, NULL);   // Set the I/O signal handler for SIGIO
    sigaction(SIGALRM, &action_timer, NULL);   // Set the timer signal handler for SIGALRM

    unique_s = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));   // Create a raw socket

    if (unique_s == -1)
    {
        perror("Socket Failed");
        return 1;
    }

    if (-1 == fcntl(unique_s, F_SETOWN, getpid()))   // Set the process ID to receive SIGIO signals
    {
        perror("fcntl setown");
        return 1;
    }

    fdfl = fcntl(unique_s, F_GETFL, NULL);   // Get the file descriptor flags

    if (fdfl == -1)
    {
        perror("fcntl f_getfl");
        return 1;
    }

    fdfl = fcntl(unique_s, F_SETFL, fdfl | O_ASYNC | O_NONBLOCK);   // Set the file descriptor flags to enable asynchronous and non-blocking mode

    if (fdfl == -1)
    {
        perror("fcntl f_setfl");
        return 1;
    }

    fds[0].fd = unique_s;   // Set the file descriptor for polling
    fds[0].events = POLLIN | POLLOUT;   // Set the events to be monitored for the file descriptor

    setitimer(ITIMER_REAL, &myt, NULL);   // Set the real-time timer

    myt.it_interval.tv_sec = 0;   // Set the interval time for the timer (seconds)
    myt.it_interval.tv_usec = TIMER_USECS;   // Set the interval time for the timer (microseconds)
    myt.it_value.tv_sec = 0;   // Set the initial expiration time for the timer (seconds)
    myt.it_value.tv_usec = TIMER_USECS;   // Set the initial expiration time for the timer (microseconds)

    sigemptyset(&mymask);   // Initialize the signal mask
    sigaddset(&mymask, SIGIO);   // Add SIGIO to the signal mask
    sigaddset(&mymask, SIGALRM);   // Add SIGALRM to the signal mask

    timeradd(&myt.it_value, &myt.it_interval, &myt.it_value);   // Add the interval time to the initial expiration time

    for (int i = 0; i < CACHE_SZ; i++)
        cache[i].occupied = 0;   // Initialize the ARP cache entries

    if (arp_resolve(inet_addr("88.80.187.1"), target_mac) == 0)   // Perform ARP resolution for the target IP address
    {
        printf("ARP Resolution Successful\n");
        printf("MAC: ");
        for (int i = 0; i < 6; i++)
            printf("%.2x:", target_mac[i]);   // Print the resolved MAC address
        printf("\n");
    }
    else
    {
        printf("ARP Resolution Failed\n");
    }

    close(unique_s);   // Close the socket

    return 0;   // Exit the program
}
