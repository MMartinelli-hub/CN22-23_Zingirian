/*
## ARP PROTOCOL FUNCTIONING ##
The Address Resolution Protocol (ARP) is a protocol used to map a network layer address (such as an IP address) to a data link layer address (such as a MAC address). 
The ARP protocol operates at the Data Link layer (Layer 2) of the OSI model.


When a device on a network needs to communicate with another device on the same network, it first checks its ARP cache to see if it has a mapping for the destination IP address. 
If it does not have a mapping, the device must send an ARP request to the network to determine the MAC address associated with the IP address.


Here is the general mechanism of ARP, as defined in RFC 826:
1. The sender creates an ARP request packet, which includes:
    - The sender's MAC address
    - The sender's IP address
    - The destination IP address (for which the sender wants to find the MAC address)
    - A broadcast MAC address (FF-FF-FF-FF-FF-FF) indicating that the request should be sent to all devices on the network

2. The ARP request packet is encapsulated in a data link layer frame and sent to the network.

3. All devices on the network receive the ARP request packet, but only the device with the specified IP address responds.

4. When the device with the specified IP address receives the ARP request packet, it creates an ARP response packet, which includes:
    - The device's MAC address
    - The device's IP address
    - The sender's MAC address (copied from the ARP request packet)
    - The sender's IP address (copied from the ARP request packet)

5. The ARP response packet is encapsulated in a data link layer frame and sent back to the sender.

6. When the sender receives the ARP response packet, it updates its ARP cache with the MAC address of the destination device.

7. The sender can now use the MAC address to communicate with the destination device.


The ARP cache is a table that stores the mappings between IP addresses and MAC addresses. 
When a device receives an ARP response, it adds the IP-to-MAC mapping to its ARP cache. 
This allows future communications with the same device to occur without the need for additional ARP requests.


ARP cache entries typically have a limited lifetime, after which they are deleted. 
The exact lifetime can vary depending on the implementation, but the default is typically around five minutes. 
This ensures that stale entries are removed from the cache and that new ARP requests are sent when necessary.
*/

/*
## ARP WORKFLOW ##
When a device wants to communicate with another device on the same network, it must determine the MAC address associated with the destination IP address.

1. Sender wants to communicate with a device on the same network with a known IP address, but an unknown MAC address.
    
2. Sender checks its ARP cache to see if it has a mapping for the destination IP address.
If the sender has a mapping for the destination IP address in its ARP cache, it can use the associated MAC address to communicate with the device. 
Otherwise, it needs to send an ARP request to the network.

3. Sender creates an ARP request packet to ask the network for the MAC address associated with the destination IP address.
The ARP request packet includes the sender's MAC address, IP address, and the destination IP address. 
The sender also sets the destination MAC address to a broadcast address (FF-FF-FF-FF-FF-FF) to indicate that the packet should be sent to all devices on the network.

4. Sender encapsulates the ARP request packet in a data link layer frame and sends it to the network.
The sender's network interface card (NIC) adds its own MAC address as the source MAC address and the broadcast MAC address as the destination MAC address to the frame.

5. All devices on the network receive the ARP request packet.
However, only the device with the specified IP address will respond.

6. Destination device receives the ARP request packet.
Upon receiving the ARP request packet, the destination device checks to see if the IP address in the packet matches its own IP address.

7. Destination device creates an ARP response packet to send back to the sender.
The ARP response packet includes the destination device's MAC address, IP address, and the sender's MAC and IP addresses (copied from the ARP request packet).

8. Destination device encapsulates the ARP response packet in a data link layer frame and sends it back to the sender.
The destination device's NIC adds its own MAC address as the source MAC address and the sender's MAC address as the destination MAC address to the frame.

9. Sender receives the ARP response packet and updates its ARP cache with the MAC address of the destination device.
The sender can now use the MAC address to communicate with the destination device.

Let see an ecxample, in which: 
    - the sender is 'Device A' 
    - the destination is 'Device B'

+-----------------------------------------------------------+
|                          Device A                          |
+-----------------------------------------------------------+
|              |                                             |
|              |                                             |
|  Application |                  Network Layer              |
|  Layer       |                  (e.g., IP)                 |
|              |                                             |
|              |                                             |
+-----------------------------------------------------------+
|             ARP (Address Resolution Protocol)              |
+-----------------------------------------------------------+
|              |                                             |
|              |                                             |
|             Data Link Layer (e.g., Ethernet)               |
|              |                                             |
|              |                                             |
+-----------------------------------------------------------+

   [Packet Structure: ARP Request]
   ========================================
   | Hardware Type   |  Protocol Type  | HLen  | PLen | Opcode |
   ========================================
   | Ethernet (0x0001)|  IP (0x0800)   |   6   |  4   | 1 (req)|
   ========================================
   | Sender MAC Address (6 bytes)             |
   ========================================
   | Sender IP Address (4 bytes)              |
   ========================================
   | Target MAC Address (6 bytes, all 0s)     |
   ========================================
   | Target IP Address (4 bytes, Destination) |
   ========================================

                                    |
                                    |
                                    | 1. Device A wants to send a packet to Device B
                                    |
                                    |
+-----------------------------------------------------------+
|                        Device A's ARP Cache                |
+-----------------------------------------------------------+
|              |                                             |
|              |                                             |
|         IP-MAC mappings, and TTLs (Time-To-Live)           |
|              |                                             |
|              |                                             |
+-----------------------------------------------------------+

                                    |
                                    |
                                    | 2. Device A checks its ARP Cache to see if it already knows
                                    |    Device B's MAC address and it is not expired
                                    |
                                    |
   +-------------------------------------------------------+
   |                                                       |
   |               ARP Cache Lookup (Cache Miss)           |
   |                                                       |
   +-------------------------------------------------------+

                                    |
                                    |
                                    |    MAC address not found in cache or expired
                                    |
                                    |
   +-------------------------------------------------------+
   |                                                       |
   |         Broadcasting ARP Request Packet               |
   |                                                       |
   +-------------------------------------------------------+

                                    |
                                    |
                                    | 3. The ARP Request Packet is broadcasted to all devices on
                                    |    the same local network as Device A
                                    |
                                    |
+-----------------------------------------------------------+
|                    Devices on the Local Network            |
+-----------------------------------------------------------+

                                    |
                                    |
                                    | 4. Device B receives the ARP Request Packet
                                    |
                                    |
   +-------------------------------------------------------+
   |                                                       |
   |               ARP Request Packet Received             |
   |                                                       |
   +-------------------------------------------------------+

                                    |
                                    |
                                    | 5. Device B updates its ARP Cache with the MAC address
                                    |    of Device A
                                    |
                                    |
+-----------------------------------------------------------+
|                        Device B's ARP Cache                |
+-----------------------------------------------------------+
|              |                                             |
|              |                                             |
|         IP-MAC mappings, and TTLs (Time-To-Live)           |
|              |                                             |
|              |                                             |
+-----------------------------------------------------------+

                                    |
                                    |
                                    | 6. Device B sends an ARP Response Packet to Device A
                                    |
                                    |
   +-------------------------------------------------------+
   |                                                       |
   |          Unicasting ARP Response Packet to A          |
   |                                                       |
   +-------------------------------------------------------+

                                    |
                                    |
                                    | 7. Device A receives the ARP Response Packet from B
                                    |
                                    |
   +-------------------------------------------------------+
   |                                                       |
   |               ARP Response Packet Received            |
   |                                                       |
   +-------------------------------------------------------+

                                    |
                                    |
                                    |
+-----------------------------------------------------------+
|                          Device A                          |
+-----------------------------------------------------------+
|              |                                             |
|              |                                             |
|  Application |                  Network Layer              |
|  Layer       |                  (e.g., IP)                 |
|              |                                             |
|              |                                             |
+-----------------------------------------------------------+
|             ARP (Address Resolution Protocol)              |
+-----------------------------------------------------------+
|              |                                             |
|              |                                             |
|             Data Link Layer (e.g., Ethernet)               |
|              |                                             |
|              |                                             |
+-----------------------------------------------------------+

   [Packet Structure: ARP Response]
   ========================================
   | Hardware Type   |  Protocol Type  | HLen  | PLen | Opcode |
   ========================================
   | Ethernet (0x0001)|  IP (0x0800)   |   6   |  4   | 2 (res)|
   ========================================
   | Sender MAC Address (6 bytes)             |
   ========================================
   | Sender IP Address (4 bytes)              |
   ========================================
   | Target MAC Address (6 bytes)             |
   ========================================
   | Target IP Address (4 bytes)              |
   ========================================

                                    |
                                    |
                                    | 8. Device A updates its ARP Cache with the MAC address
                                    |    of Device B
                                    |
                                    |
+-----------------------------------------------------------+
|                        Device A's ARP Cache                |
+-----------------------------------------------------------+
|              |                                             |
|              |                                             |
|         IP-MAC mappings, and TTLs (Time-To-Live)           |
|              |                                             |
|              |                                             |
+-----------------------------------------------------------+

                                    |
                                    |
                                    | 9. Device A sends the original packet to Device B
                                    |
                                    |
+-----------------------------------------------------------+
|                          Device B                          |
+-----------------------------------------------------------+
|              |                                             |
|              |                                             |
|  Application |                  Network Layer              |
|  Layer       |                  (e.g., IP)                 |
|              |                                             |
|              |                                             |
+-----------------------------------------------------------+
|             Ethernet (Data Link Layer)                     |
+-----------------------------------------------------------+
|              |                                             |
|              |                                             |
|             Physical Layer (e.g., Cables, Wireless)        |
|              |                                             |
|              |                                             |
+-----------------------------------------------------------+

*/

// ## IMPLEMENTATION ##

// Headers
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
 * ARP Cache Implementation
 *
 * This program implements an ARP cache. 
 * It resolves IP addresses to MAC addresses using the ARP protocol.
 * The main function iterates over a range of IP addresses, resolves each IP address using the `arp_resolve` function,
 * and prints the corresponding MAC address.
 */

// Constants for the cache timeout and maximum cache size
#define CACHE_SZ	100
#define CACHE_TIMEOUT 60 // seconds


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


// ARP cache entries structure
struct arp_cache {
    unsigned int ip;
    unsigned char mac[6];
    unsigned int t_created;
    unsigned char occupied;
} cache[CACHE_SZ]; // ARP cache of size 100


// Function declarations
void forge_eth(struct ethernet_frame *eth, unsigned char *dst, unsigned short type);

#define MAXFRAME 10000
#define TIMER_USECS 100000
int pkts = 0;
struct sigaction action_io, action_timer;
sigset_t mymask;
unsigned char l2buffer[MAXFRAME];
struct sockaddr_ll;
struct pollfd fds[1];
int fdfl;
long long int tick = 0;
int unique_s;
int fl;
struct sockaddr_ll sll;

/*
Prints the buffer content in hexadecimal and decimal format

Prints the content of a buffer as hexadecimal values.

Parameters:
- b: Pointer to the buffer
- size: Size of the buffer

Returns: None
 */
int printbuf(void *b, int size) {
    int i;
    unsigned char *c = (unsigned char *)b;
    for (i = 0; i < size; i++)
        printf("%.2x(%.3d) ", c[i], c[i]);
    printf("\n");
}

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

    for (int i = 0; i < CACHE_SZ; i++) {
        if (cache[i].occupied) {
            if (cache[i].ip == ipaddr) {
                for (int k = 0; k < 6; k++)
                    mac[k] = cache[i].mac[k];
                return 0;
            }
        }
    }

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
    printf("ARP Request");

    // Send ARP request
    for (int i = 0; i < sizeof(struct sockaddr_ll); i++)
        ((char *)&sll)[i] = 0;
    sll.sll_family = AF_PACKET;
    sll.sll_ifindex = if_nametoindex("eth0");
    len = sizeof(struct sockaddr_ll);
    t = sendto(unique_s, buffer, 64, 0, (struct sockaddr *)&sll, len);
    if (t == -1) {
        perror("sendto Failed");
        return 1;
    }

    unsigned int time = tick;

    // Wait for ARP response
    while (pause()) {
        for (int i = 0; i < CACHE_SZ; i++) {
            if (cache[i].occupied) {
                if (cache[i].ip == ipaddr) {
                    for (int k = 0; k < 6; k++)
                        mac[k] = cache[i].mac[k];
                    return 0;
                }
            }
        }

        if (tick - time >= 3)
            return -1;
    }
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
    struct itimerval myt;
    
    // Block SIGIO and SIGALRM signals to avoid interference during the execution of the signal handler.
    if (-1 == sigprocmask(SIG_BLOCK, &mymask, NULL)) {
        perror("sigprocmask");
        return;
    }
    
    // Increment the overlap counter
    fl++;
    
    // Check if there is an overlap (multiple signal handler executions occurring simultaneously or in rapid succession).
    if (fl > 1) {
        printf("Overlap Detected: Multiple timer signals processed concurrently.\n");
        // Perform any necessary handling or synchronization to deal with the overlap.
        // This may involve adjusting the program's behavior or data structures to avoid conflicts.
    }
    
    // Decrement the overlap counter
    fl--;
    
    // Unblock SIGIO and SIGALRM signals
    if (-1 == sigprocmask(SIG_UNBLOCK, &mymask, NULL)) {
        perror("sigprocmask");
        return;
    }
    
    // Iterate through the cache entries and check for expired entries
    for (i = 0; i < CACHE_SZ; i++) {
        if (cache[i].occupied) {
            // If the entry has been in the cache for more than 300 seconds, mark it as unoccupied
            if (tick - cache[i].t_created >= 300)
                cache[i].occupied = 0;
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
void myio(int number) {
    int len, size;

    // Declare a pointer to the Ethernet frame structure and assign it to the beginning of the received L2 buffer
	struct ethernet_frame *eth = (struct ethernet_frame *)l2buffer;

	// Declare a pointer to the ARP packet structure and assign it to the payload field within the Ethernet frame
	struct arp_packet *arp = (struct arp_packet *)eth->payload;

    // Block the signals
    if (-1 == sigprocmask(SIG_BLOCK, &mymask, NULL)) {
        perror("sigprocmask");
        return;
    }
    
	fl++; // Increment the value of the 'fl' variable to track the number of overlaps

	if (fl > 1)
		printf("Overlap (%d) in myio\n", fl); // Print a warning message if there are multiple overlaps

    // Poll for incoming packets
    if (poll(fds, 1, 0) == -1) {
        perror("Poll failed");
        return;
    }
    
    // Check if there is data available on the socket
    if (fds[0].revents & POLLIN) {
        len = sizeof(struct sockaddr_ll);

        // Receive packet from the socket
        while (0 <= (size = recvfrom(unique_s, l2buffer, MAXFRAME, 0, (struct sockaddr *)&sll, &len))) {
            pkts++;

            // Check if the received packet is an ARP packet
            if (eth->type == htons(0x0806)) {
                // Check if the ARP operation is a reply
                if (arp->op == htons(2)) {
                    // Process the ARP reply and update the cache
                    for (int i = 0; i < CACHE_SZ; i++) {
                        if (!cache[i].occupied) {
                            cache[i].occupied = 1;
                            cache[i].t_created = tick;
                            
                            // Extract the source IP address from the ARP reply
                            for (int j = 0; j < 4; j++)
                                ((unsigned char *)(&cache[i].ip))[j] = arp->srcip[j];
                            
                            // Extract the source MAC address from the ARP reply
                            for (int j = 0; j < 6; j++)
                                cache[i].mac[j] = arp->srcmac[j];
                            
                            break;
                        }
                    }
                }
            }
        }

        // Check if there was an error receiving the packet
        if (errno != EAGAIN) {
            perror("Packet recvfrom Error\n");
        }
    }

    // Update the poll events and handle overlapping signals
    fds[0].events = POLLIN | POLLOUT;
    fds[0].revents = 0;
    
    if (fl > 1)
        printf("Overlap (%d) in myio\n", fl);

    fl--;

    // Unblock the signals
    if (-1 == sigprocmask(SIG_UNBLOCK, &mymask, NULL)) {
        perror("sigprocmask");
        return;
    }
}


int main(int argc, char **argv) {
    unsigned char target_ip[4] = {88, 80, 187, 1}; // The target IP address to resolve
    unsigned char target_mac[6]; // Variable to store the resolved MAC address
    clock_t start;
    fl = 0; // Variable to track signal overlap

    struct itimerval myt; // Structure to configure the timer

    if (argc != 3) {
        printf("usage: %s <first byte> <last byte>\n", argv[0]); // Print usage information if the command-line arguments are incorrect
        return 1;
    }

    action_io.sa_handler = myio; // Assign the callback function myio to handle I/O signals
    action_timer.sa_handler = mytimer; // Assign the callback function mytimer to handle timer signals
    sigaction(SIGIO, &action_io, NULL); // Register the I/O signal handler
    sigaction(SIGALRM, &action_timer, NULL); // Register the timer signal handler

    unique_s = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL)); // Create a raw socket to capture all Ethernet frames
    if (unique_s == -1) {
        perror("socket: "); // Print an error message if the socket creation fails
        return 1;
    }

    fcntl(unique_s, F_SETOWN, getpid()); // Set the process ID that will receive the asynchronous I/O signals
    fcntl(unique_s, F_SETFL, FASYNC); // Enable asynchronous I/O mode for the socket

    fds[0].fd = unique_s; // Initialize the file descriptor structure for polling
    fds[0].events = POLLIN | POLLOUT; // Set the events to poll for (input and output)

    if (-1 == sigemptyset(&mymask)) { // Initialize an empty signal mask
        perror("sigemptyset");
        return 1;
    }

    if (-1 == sigaddset(&mymask, SIGIO)) { // Add the SIGIO signal to the mask
        perror("sigaddset");
        return 1;
    }

    if (-1 == sigaddset(&mymask, SIGALRM)) { // Add the SIGALRM signal to the mask
        perror("sigaddset");
        return 1;
    }

    if (-1 == sigprocmask(SIG_BLOCK, &mymask, NULL)) { // Block the signals in the mask to prevent their delivery
        perror("sigprocmask");
        return 1;
    }

    myt.it_interval.tv_sec = 0; // Set the interval between timer expirations (seconds)
    myt.it_interval.tv_usec = TIMER_USECS; // Set the interval between timer expirations (microseconds)
    myt.it_value.tv_sec = 0; // Set the initial timer expiration (seconds)
    myt.it_value.tv_usec = TIMER_USECS; // Set the initial timer expiration (microseconds)
    if (-1 == setitimer(ITIMER_REAL, &myt, NULL)) { // Set the real-time timer to send periodic signals
        perror("setitimer");
        return 1;
    }

    start = clock(); // Get the current clock time
    unsigned int ip;
    unsigned char mac[6];
    unsigned char *ipbytes = (unsigned char *)&ip; // Convert the IP address to bytes
    ipbytes[0] = atoi(argv[1]); // Convert the first byte of the command-line argument to an integer and assign it to the IP address
    ipbytes[1] = atoi(argv[2]); // Convert the second byte of the command-line argument to an integer and assign it to the IP address
    ipbytes[2] = 0; // Set the remaining bytes of the IP address to 0
    ipbytes[3] = 0;
    ip = ntohl(ip); // Convert the IP address from network byte order to host byte order

    while (ip != 0) {
        if (arp_resolve(ip, mac) == 0) { // Resolve the MAC address for the current IP address using ARP
            printf("IP: %d.%d.%d.%d - MAC: %.2X:%.2X:%.2X:%.2X:%.2X:%.2X\n", ipbytes[0], ipbytes[1], ipbytes[2], ipbytes[3], mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]); // Print the resolved IP and MAC addresses
        } else {
            printf("IP: %d.%d.%d.%d - MAC not found\n", ipbytes[0], ipbytes[1], ipbytes[2], ipbytes[3]); // Print a message indicating that the MAC address was not found
        }
        ip++; // Increment the IP address
    }

    printf("Time elapsed: %.2f seconds\n", (double)(clock() - start) / CLOCKS_PER_SEC); // Print the elapsed time in seconds

    return 0;
}
