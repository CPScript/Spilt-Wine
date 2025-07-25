> Run with:
> * `sudo python3 main.py` (basic capture)
> * `sudo python3 main.py -p 80 443 22` (port filtering)
> * `sudo python3 main.py -i eth0 -c 100` (interface-specific capture with packet limit).

---

**Raw Socket Implementation**: Uses `AF_PACKET` sockets on Linux for full Ethernet frame access and `AF_INET` raw sockets on Windows. Handles platform-specific differences in packet structure access.

**Packet Parsing Architecture**: Implements layered parsing following the OSI model - Ethernet (Layer 2), IP (Layer 3), and TCP/UDP (Layer 4). Each parser extracts relevant fields using `struct.unpack()` with network byte order.

**Protocol Support**: Handles TCP (protocol 6), UDP (protocol 17), and ICMP (protocol 1) with full header field extraction including TCP flags, sequence numbers, and port information.

**Memory Management**: Uses `defaultdict` and `set` collections for efficient statistics tracking without memory leaks during extended capture sessions.

**Execution Requirements**: Requires root privileges on Linux or Administrator privileges on Windows due to raw socket access restrictions. The code includes proper privilege checking and error handling.
