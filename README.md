# CN22-23_Zingirian

## Particularly noticeable:
- [02_ping.c](https://github.com/MMartinelli-hub/CN22-23/blob/main/02_ping.c)
- [Exam-11-07-2018_Ping_Nat.c](https://github.com/MMartinelli-hub/CN22-23/blob/main/Exercises/Exam-11-07-2018_Ping_Nat.c)
- [Exam-19-06-2018_Ping_SynAck.c](https://github.com/MMartinelli-hub/CN22-23/blob/main/Exercises/Exam-19-06-2018_Ping_SynAck.c)
- [Exam-21-06-2017_Tcp_WindowScale.c](https://github.com/MMartinelli-hub/CN22-23/blob/main/Exercises/Exam-21-06-2017_Tcp_WindowScale.c)
- [Exam-26-07-2022_Tcp_Sack.c](https://github.com/MMartinelli-hub/CN22-23/blob/main/Exercises/Exam-26-07-2022_Tcp_Sack.c)

## Table of Contents:
### Main folder:
- **01_sniffer.c**: Simple network sniffer.
- **02_ping.c**: This program performs ICMPs (ping) and TCPs operations to a destination IP address and receive the corresponding responses.
- **03_env.c**: This program demonstrates the usage of asynchronous I/O, support for timeout, and non-blocking I/O.
- **04_selrep.c**: Selective Repeat Protocol Implementation.
- **05_gobackn.c**: Go-Back-N Protocol Implementation.
- **06_arpcache.c**: ARP caching Implementation.
- **07_environ.c**: ARP resolver implementation.
- **08_tcp.c**: A (really chaotic) 3-Way Handshake TCP implementation.

### Exercises:
- **Es6_Ping_IcmpTimeExcedeed.c**: Modify the ping so that the ttl is small enough for preventing the packet reaching destination. Intercept the ICMP "Time Excedeed" message and manage it.
- **Es7_Ping_IcmpUnreachableDest.c**: Modify the ping.c program so that it is able to recognize, in reception, as well as the usual ICMP "message echo reply", also another type of ICMP message, called "unreachable destination".
- **Es8_Ping_Statistics.c**: Modify the ping.c program to make it able to receive ethernet frames from the network and calculate statistics on all ethernet packets and on all IP packets.
- **Es9_Ping_RecordRoute.c**: Modify the ping.c program adding the "Record Route" option in the IP datagram.
- **Es10_Ping_TcpConnection.c**: Modify the program ping.c, so that, instead of sending a request of the icmp echo request type on an IP packet, it sends a request for TCP connection to a web service on an IP packet addressed to 147.162..X, waits for and processes the reply.
- **Exam-11-07-2018_Ping_Nat.c**: Modify the ping.c program so that it acts like a NAT from origin to Google homepage.
- **Exam-19-06-2018_Ping_SynAck.c**: Modify the ping.c program so that it is able to forge TCP responses.
- **Exam-22-07-2014_Ping_IcmpSplit**: Modify the ping.c program so that it sends the IP payload split in two parts.
- **Exam-29-01-2021_Ping_UnreachableDest**: Modify the ping.c program so that it is able to recognize, in reception, the ICMP message "unreachable destination", and supports the correct handling.
- **Exam-20-07-2021_Tcp_UnreachableDest.c**: Modify the tcp.c program so that it is able to recognize, in reception, the ICMP message "unreachable destination", and supports the correct handling.
- **Exam-21-06-2017_Tcp_WindowScale.c**: Modify the tcp.c program so that it is able to support the 'Window Scale' TCP option.
- **Exam-23-06-2022_TcpRttm.c**: Modify the tcp.c program so that it is able to support the 'Round Trip Time' TCP option.
- **Exam-25-06-2021_Tcp_MSS.c**: Modify the tcp.c program so that it is able to support the 'Maximum Segment Size' TCP option.
- **Exam-26-07-2022_Tcp_Sack.c**: Modify the tcp.c program so that it is able to support the 'Selective Acknowledgment' TCP option.
 
### See also [this repo](https://github.com/nicomazz/ComputerNetworks-unipd2018).

## Useful RFCs
- [RFC791](https://tools.ietf.org/html/rfc791) IP
- [RFC792](https://tools.ietf.org/html/rfc792) ICMP
- [RFC793](https://tools.ietf.org/html/rfc793) TCP
- [RFC826](https://tools.ietf.org/html/rfc826) ARP
- [RFC1945](https://tools.ietf.org/html/rfc1945) HTTP1
- [RFC2616](https://tools.ietf.org/html/rfc2616) HTTP1.1

## Something to understand before trying the past exams

An Ethernet frame (data link layer) contains an IP datagram (network layer) that can contains one of the following { tcp_segment (transport layer), icmp_packet } (for the purpose of this exam). An easy way to realize that is:

```c
eth = (struct eth_frame *)buffer;
ip = (struct ip_datagram *)eth->payload;

tcp = (struct tcp_segment *)ip->payload;
// or
icmp = (struct icmp_packet *)ip->payload;
```
#### Data types and endianess
<details>
<summary>Data types and endianess</summary>

(depends on the architecture, but you can assume that the following is true for this exam)

- `unsigned char` : 1 byte
- `unsigned short`: 2 bytes
- `unsiged int` : 4 bytes

To transfer on the network is used Big endian. Most of the intel's cpus are little endian. To convert use this 2 functions that automatically understand if a conversion is needed:
-  `htonl(x)` or `htons(x)` to convert x from **H**ost **to** **N**etwork endianess, **l** if you have to convert a 4 bytes variable, **s** a 2 bytes one.
- `ntohl(x)` or `ntohs(x)` for the opposite. (You may notice that the implementation of htonx and ntohx is the same)
- if a variable is 1 byte long we don't have endianess problems (obviously)
 </details>


#### Ethernet frame
<details><summary>Ethernet frame</summary>
<p>

![Ethernet frame](https://upload.wikimedia.org/wikipedia/commons/thumb/4/42/Ethernet_frame.svg/800px-Ethernet_frame.svg.png)

```c
// Frame Ethernet
struct eth_frame {
   unsigned char dst[6]; // mac address
   unsigned char src[6]; // mac address
   unsigned short type;  // 0x0800 = ip, 0x0806 = arp
   char payload[1500];   //ARP or IP
 };
```
Thanks to the `type` we can understand where to forward it on the next level (2 examples are ip or arp)

</p>
</details>


#### IP datagram
<details><summary>IP datagram</summary>
<p>

![Ip datagram](http://www.danzig.jct.ac.il/tcp-ip-lab/ibm-tutorial/3376f11.gif)

Header length: check second half of `ver_ihl` attribute. Example: if it's '5', then the header length is **4** * 5 = 20 bytes.  
//todo add image
```c
// Datagramma IP
struct ip_datagram{
   unsigned char ver_ihl;    // first 4 bits: version, second 4 bits: (lenght header)/8
   unsigned char tos;        //type of service
   unsigned short totlen;    // len header + payload
   unsigned short id;        // useful in case of fragmentation
   unsigned short flags_offs;//offset/8 related to the original ip package
   unsigned char ttl;
   unsigned char protocol;   // TCP = 6, ICMP = 1
   unsigned short checksum;  // only header checksum (not of payload). Must be at 0 before the calculation.
   unsigned int src;         // ip address
   unsigned int dst;         // ip address
   unsigned char payload[1500];
};
```

</p>
</details>


#### TCP segment

<details><summary>TCP segment</summary>
<p>

![tcp segment](https://i.ibb.co/WpSwRXL/Screen-Shot-2019-01-07-at-22-15-38.png)

Header (as defined here) length: `20`
```c
struct tcp_segment {
   unsigned short s_port;
   unsigned short d_port;
   unsigned int seq;        // offset in bytes from the start of the tcp segment in the stream (from initial sequance n)
   unsigned int ack;        // useful only if ACK flag is 1. Next seq that sender expect
   unsigned char d_offs_res;// first 4 bits: (header len/8)
   unsigned char flags;            // check rfc
   unsigned short win;      // usually initially a 0 (?)
   unsigned short checksum; // use tcp_pseudo to calculate it. Must be at 0 before the calculation.
   unsigned short urgp;            
   unsigned char payload[1000];
};
```
To calculate the checksum of a TCP segment is useful to define an additional structure (check on the relative RFC). Size of it, without the tcp_segment part
```c
struct tcp_pseudo{
   unsigned int ip_src, ip_dst;
   unsigned char zeroes;
   unsigned char proto;        // ip datagram protocol field (tcp = 6, ip = 1)
   unsigned short entire_len;  // tcp length (header + data)
   unsigned char tcp_segment[20/*to set appropriatly */];  // entire tcp packet pointer
};
```
To calculate the size of the entire tcp segment (or of the icmp), or more in general of the ip payload:
```c
unsigned short ip_total_len = ntohs(ip->totlen);
unsigned short ip_header_dim = (ip->ver_ihl & 0x0F) * 4;
int ip_payload_len = ip_total_len-ip_header_dim;
```
</p>
</details>


#### Checksum calculation

<details><summary>Checksum calculation</summary>
<p>

We can use this function both for the IP datagram and the TCP segment,
but we must take care about the `len` parameter.

- [ ] todo: take care about minimum size for tcp, and odd/even corner case

```c
unsigned short checksum( unsigned char * buffer, int len){
   int i;
   unsigned short *p;
   unsigned int tot=0;
   p = (unsigned short *) buffer;
   for(i=0;i<len/2;i++){
      tot = tot + htons(p[i]);
      if (tot&0x10000) tot = (tot&0xFFFF)+1;
   }
   return (unsigned short)0xFFFF-tot;
}
```
The 2 cases are:
- IP: `ip->checksum=htons(checksum((unsigned char*) ip, 20));`
`
- TCP:
```c
int TCP_TOTAL_LEN = 20;
struct tcp_pseudo pseudo; // size of this: 12
memcpy(pseudo.tcp_segment,tcp,TCP_TOTAL_LEN);
pseudo.zeroes = 0;
pseudo.ip_src = ip->src;
pseudo.ip_dst = ip->dst;
pseudo.proto = 6;
pseudo.entire_len = htons(TCP_TOTAL_LEN); // may vary
tcp->checksum = htons(checksum((unsigned char*)&pseudo,TCP_TOTAL_LEN+12));
```


</p>
</details>

#### Convert int IP address in string

<details><summary>Convert int IP address in string</summary>
<p>

```c
#include <arpa/inet.h>

void print_ip(unsigned int ip){
   struct in_addr ip_addr;
   ip_addr.s_addr = ip;
   printf("%s\n",inet_ntoa(ip_addr));
}

```

</p>
</details>

#### Useful utils to print packet contents
<details>
<summary> Ethernet packet </summary>
	
```c
void stampa_eth( struct eth_frame* e ){
	printf( "\n\n ***** PACCHETTO Ethernet *****\n" );
	printf( "Mac destinazione: %x:%x:%x:%x:%x:%x\n", e->dst[0], e->dst[1], e->dst[2], e->dst[3], e->dst[4], e->dst[5] );
	printf( "Mac sorgente: %x:%x:%x:%x:%x:%x\n", e->src[0], e->src[1], e->src[2], e->src[3], e->src[4], e->src[5] );
	printf( "EtherType: 0x%x\n", htons( e->type ) );
}
```
</details>

<details>
<summary> IP datagram </summary>
	
```c
void stampa_ip( struct ip_datagram* i ){
	unsigned int ihl = ( i->ver_ihl & 0x0F) * 4; // Lunghezza header IP
	unsigned int totlen = htons( i->totlen );    // Lunghezza totale pacchetto
	unsigned int opt_len = ihl-20;         // Lunghezza campo opzioni
	
	printf( "\n\n ***** PACCHETTO IP *****\n" );
	printf( "Version: %d\n", i->ver_ihl & 0xF0 );
	printf( "IHL (bytes 60max): %d\n", ihl );
	printf( "TOS: %d\n", i->tos );
	printf( "Lunghezza totale: %d\n", totlen );
	printf( "ID: %x\n", htons( i->id ) );
	unsigned char flags = (unsigned char)( htons( i->flag_offs) >>  13);
	printf( "Flags: %d | %d | %d \n", flags & 4, flags & 2, flags & 1 );
	printf( "Fragment Offset: %d\n", htons( i->flag_offs) & 0x1FFF  );
	printf( "TTL: %d\n", i->ttl );
	printf( "Protocol: %d\n", i->proto );
	printf( "Checksum: %x\n", htons( i->checksum ) );
	
	unsigned char* saddr = ( unsigned char* )&i->saddr;
	unsigned char* daddr = ( unsigned char* )&i->daddr;
	
	printf( "IP Source: %d.%d.%d.%d\n", saddr[0], saddr[1], saddr[2], saddr[3] );
	printf( "IP Destination: %d.%d.%d.%d\n", daddr[0], daddr[1], daddr[2], daddr[3] );
	
	if( ihl > 20 ){
		// Stampa opzioni
		printf( "Options: " );
		for(int j=0; j < opt_len ; j++ ){
			printf("%.3d(%.2x) ", i->payload[j], i->payload[j]);
		}
		printf( "\n" );
	}
}
```
</details>

<details>
<summary> ARP </summary>
	
```c
void stampa_arp( struct arp_packet* a ){
	printf( "\n\n ***** PACCHETTO ARP *****\n" );
	printf( "Hardware type: %d\n", htons( a->htype ) );
	printf( "Protocol type: %x\n", htons( a->ptype ) );
	printf( "Hardware Addr len: %d\n", a->hlen );
	printf( "Protocol Addr len: %d\n", a->plen );
	printf( "Operation: %d\n", htons( a->op ) );
	printf( "HW Addr sorgente: %x:%x:%x:%x:%x:%x\n", a->hsrc[0], a->hsrc[1], a->hsrc[2], a->hsrc[3], a->hsrc[4], a->hsrc[5] );
	printf( "IP Source: %d.%d.%d.%d\n", a->psrc[0], a->psrc[1], a->psrc[2], a->psrc[3] );
	printf( "HW Addr Destinazione: %x:%x:%x:%x:%x:%x\n", a->hdst[0], a->hdst[1], a->hdst[2], a->hdst[3], a->hdst[4], a->hdst[5] );	
	printf( "IP Dest: %d.%d.%d.%d\n", a->pdst[0], a->pdst[1], a->pdst[2], a->pdst[3] );
}
```
</details>

<details>
<summary> ICMP content </summary>
	
```c
void stampa_icmp( struct icmp_packet* i ){
	printf( "\n\n ***** PACCHETTO ICMP *****\n" );
	printf( "Type: %d\n", i->type );
	printf( "Code: %d\n", i->code );
	printf( "Code: 0x%x\n", htons( i->checksum ) );
	printf( "ID: %d\n", htons(i->id) );
	printf( "Sequence: %d\n", htons(i->seq) );
}
```
</details>

<details>
<summary> TCP </summary>
	
```c
void stampa_tcp( struct tcp_segment* t ){
	printf( "\n\n ***** PACCHETTO TCP *****\n" );
	printf( "Source Port: %d\n", htons( t->s_port ) );
	printf( "Source Port: %d\n", htons( t->d_port ) );
	printf( "Sequence N: %d\n", ntohl( t->seq ) );
	printf( "ACK: %d\n", ntohl( t->ack ) );
	printf( "Data offset (bytes): %d\n", ( t->d_offs_res >> 4 ) * 4 );
	printf( "Flags: " );
	printf( "CWR=%d | ", (t->flags & 0x80) >> 7 );
	printf( "ECE=%d | ", (t->flags & 0x40) >> 6 );
	printf( "URG=%d | ", (t->flags & 0x20) >> 5 );
	printf( "ACK=%d | ", (t->flags & 0x10) >> 4 );
	printf( "PSH=%d | ", (t->flags & 0x08) >> 3 );
	printf( "RST=%d | ", (t->flags & 0x04) >> 2 );
	printf( "SYN=%d | ", (t->flags & 0x02) >> 1 );
	printf( "FIN=%d\n",  (t->flags & 0x01) );
	printf( "Windows size: %d\n", htons( t->win ) );
	printf( "Checksum: 0x%x\n", htons( t->checksum ) );
	printf( "Urgent pointer: %d\n", htons( t->urgp ) );
}
```
</details>

#### How to printf the various things

Not really useful, but..

```c
// es. tcp.c
printf("%.4d.  // delta_sec (unsigned int)
   %.6d        // delta_usec
   %.5d->%.5d  // ports (unsigned short)
   %.2x        // tcp flags (unsigned char) in hex: es: "12"
   %.10u       // seq (unsigned int)
   %.10u       // ack
   %.5u        //tcp win   
   %4.2f\n", delta_sec, delta_usec, htons(tcp->s_port), htons(tcp->d_port), tcp->flags, htonl(tcp->seq) - seqzero, htonl(tcp->ack) - ackzero, htons(tcp->win), (htonl(tcp->ack) - ackzero) / (double)(delta_sec * 1000000 + delta_usec));

```

# Useful tips

Useful info

**/etc/services**: To know all the TCP ports available at the application level.

**/etc/protocols**. Know assigned Internet Protocol Numbers. In the IPv4 there is an 8 bit field "Protocol" to identify the next level protocol.In IPv6 this field is called the "Next Header" field.

**nslookup <URL>**: finds the ip address of the specified URL (example: www.google.com)

**netstat -rn** shows routing table

**traceroute <URL>** routes an ip packet in which path it travels by printing the IP of every gateway that decides to drop the packet that was forged with low TTL (time to live, decremented on every hop) count.

# How to use curl

curl is a command-line tool to transfer data from or to a server, using one of the supported protocols (DICT, FILE, FTP, FTPS, GOPHER, **HTTP**, **HTTPS**, IMAP,
       IMAPS, LDAP, LDAPS, POP3, POP3S, RTMP, RTSP, SCP, SFTP, SMB, SMBS, SMTP, SMTPS, TELNET and TFTP)
    
## Example request
    $ curl http://example.com/
    
## Example verbose request, useful for debugging 
    $ curl -v http://example.com/
    
## Send Curl request using Custom Header
    $ curl -v http://example.com/ --headers [OR -H] "HeaderName: HeaderValue"
    
## Send Curl request using Basic Authentication, --basic is the default authentication mechanism so no need to specify it
    $ curl -v http://example.com/ -u "username:password"
    
## Send curl request through a proxy, we have seen HTTP proxy
    $ curl -v http://example.com/ --proxy [OR -x] http://SERVER:PORT

# How to use Vim and other tips

## Preconditions
**Copy the .vimrc file into your home directory on the server using Unix's scp command**.

Remember to change MATRICOLA with your Unipd Student ID.

Login using your SSH credentials.

    scp -O ./.vimrc MATRICOLA@SERVER_IP:/home/MATRICOLA/.vimrc 


## Content of .vimrc
This .vimrc config file allows you to:
- **Use your mouse**: scrolling wheel to move up or down, click and point
- **Move line Up/Down** using Ctrl+Shift+Up/Down
- Press F8 to **Compile** the **C** program **without exiting Vim**
- Press F9 to **Execute** the **C** program **without exiting Vim**
- Auto close brackets

## Other configurations:
- Replace tabs with 3 spaces
- Highlight matching parentheses
- Auto indent on brackets
- Show line number
- Highlight current line
- Search characters as they are entered
- Search is case insesitive if no case letters are entered, but case sensitive if case letters are entered
- Highlight search results


# How to search in VIM:
<details>
<summary>Click to expand!</summary>

<br>

Search is **UNIDIRECTIONAL** but when the search reach one end of the file, pressing **n** continues the search, starting from the other end of the file.

## Search from the current line **forward**/**backwards**

To search forward use /

To search bacward use ?

x es:

    ESC (go into Command mode)

    /query (forward)
    ?query (backward)

    ENTER (to stop writing in the search query)

    (now all search results of the query are highlighted)

    n (to move to the NEXT occurence in the search results)
    N (to move to the PREVIOUS occurence in the search results)

    ESC (to exit Search mode)
</details>


# How to Compile and Execute without exiting VIM:
<details>
<summary>Click to expand!</summary>

To Compile press F8

To Execute press F9

    ESC (go into Command mode)

    F8 (compile shortcut)
    F9 (execute shortcut)

    CTRL+C (to exit compilation/executable) 

    Enter (to re-enter in vim)
</details>



# How to Move current line Up or Down in VIM:
<details>
<summary>Click to expand!</summary>

    ESC (go into Command mode)

    CTRL+SHIFT+PAGE UP  (to move line up)
    CTRL+SHIFT+PAGE DOWN (to move line down)

    i (go into Insert mode)
</details>


# How to Select, Copy/Cut and Paste in VIM:
<details>
<summary>Click to expand!</summary>

    Select with the mouse the text you want to copy
    [ALTERNATIVE
        ESC (go into Command mode)
        V100G (to select from current line to line 100, included, using Visual mode)]

    y (to Copy/yank)
    d (to Cut/delete)

    p (to Paste after the cursor)
</details>

# How to copy from another file in VIM:
<details>
<summary>Click to expand!</summary>

Open the file from which you want to copy in Vim using:

    vi ogFile.c (ogFile is the destination file)

    ESC (go into Command mode)

    :ePATH/file (open 'source' file at Path)

    (select the lines that you want to copy)
    y (copy/yank)

    :q (close the 'source' file)

    vi ogFile.c (open the 'destination' file)

    p (paste the copied lines into the 'destination' file)
</details>



# If you've made an error, CTRL+z is u:
<details>
<summary>Click to expand!</summary>
    
    ESC (go into Command mode)

    u (to Undo)
</details>


# If you've pressed CTRL + s and now the screen is frozen, press CTRL + q (to unfreeze screen)
<details>
<summary>Click to expand!</summary>

    CTRL + s (now screen is frozen)

    (every command that you type when the screen is frozen will be executed, it just won't be displayed in the terminal)

    CTRL + q (to unfreeze the screen)
</details>
