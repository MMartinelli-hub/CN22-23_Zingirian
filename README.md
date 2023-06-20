# CN22-23_Zingirian

## Particularly noticeable:
- [02_ping.c](https://github.com/MMartinelli-hub/CN22-23/blob/main/02_ping.c)
- [Exam11072018_Ping_Nat.c](https://github.com/MMartinelli-hub/CN22-23/blob/main/Exercises/Exam11072018_Ping_Nat.c)
- [Exam19062018_Ping_SynAck.c](https://github.com/MMartinelli-hub/CN22-23/blob/main/Exercises/Exam19062018_Ping_SynAck.c)

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
- **Exam200621_Tcp_UnreachableDest.c**: Modify the tcp.c program so that it is able to recognize, in reception, the ICMP message "unreachable destination", and supports the correct handling.
- **Exam220714_Ping_IcmpSplit**: Modify the ping.c program so that it sends the IP payload split in two parts.
- **Exam250621_Tcp_MSS.c**: Modify the tcp.c program to support the MSS option.
- **Exam290121_Ping_UnreachableDest**: Modify the ping.c program so that it is able to recognize, in reception, the ICMP message "unreachable destination", and supports the correct handling.
- **Exam09072013_Ping_EchoReply.c**: Modify the ping.c program so that it is able to forge echo responses.
- **Exam11072018_Ping_Nat.c**: Modify the ping.c program so that it acts like a NAT from origin to Google homepage.
- **Exam19062018_Ping_SynAck.c**: Modify the ping.c program so that it is able to forge TCP responses.