# PubSub Tunnel

A simple network tunning mechanism for Pub/Sub transports

Tunnels traffic at layer 3 (IP) of the OSI model

### Mechanism

This library uses `libpcap` internally to capture packets from the
loopback interface and send them through the provided Pub/Sub transport.

The tunneling mechanism has 2 roles: `Server` and `Client`.

0. Server subscribes to a `<tunnel-topic>` and is ready for tunneling sessions
0. Client generates a session ID (128 bit) and start forwarding packets from a
    preconfigured address on the loopback interface to `<tunnel-topic>` prepended
    by the session ID
0. Client subscribes to `<tunnel-topic>/base64url(<session-id>)` and performs NAT
    on received IP packets to first loopback address (127.0.0.1) before injecting it
0. Server upon receiving a new session ID allocates an IP in the loopback block
    (127.0.0.0/8) in a preconfigured range and performs NAT on the IP packet
    to the first loopback address (127.0.0.1) before injecting it in the interface
0. Server starts forwarding packets from the allocated address to
    `<tunnel-topic>/base64url(<session-id>)`

Note that IPs in the preconfigured range on the loopback block will be reused
in a LRU fasion, make sure the range is large enough such that new sessions will
not override existing ones.
