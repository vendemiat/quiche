# DNS over QUIC (DoQ) Examples

This directory contains example implementations of DNS over QUIC (DoQ) as specified in [RFC 9250](https://datatracker.ietf.org/doc/html/rfc9250).

## Overview

DoQ provides transport confidentiality for DNS using QUIC. It combines the privacy properties of DNS over TLS (DoT) with the performance benefits of QUIC, including:

- Reduced connection establishment latency
- Better packet loss recovery
- No head-of-line blocking
- Support for 0-RTT data

## Examples

All DoQ examples require the `doq` feature flag. Run the commands below
from the repository root.

### DoQ Client (`doq-client.rs`)

A simple DoQ client that sends DNS queries to a DoQ server.

```bash
# Build the example
cargo build --example doq-client --features doq

# Query an A record
cargo run --example doq-client --features doq -- 127.0.0.1 example.com A

# Query an AAAA record
cargo run --example doq-client --features doq -- 127.0.0.1 example.com AAAA

# Query using IPv6
cargo run --example doq-client --features doq -- ::1 example.com

# Query a public DoQ server by host name (h.root-servers.net supports DoQ)
cargo run --example doq-client --features doq -- h.root-servers.net . SOA
```

The server argument accepts an IP (`192.0.2.1`), an IP with port
(`192.0.2.1:853`), a bracketed IPv6 literal (`[::1]` or `[::1]:853`), or a host
name (`h.root-servers.net`), which is resolved via the system resolver and used
as the TLS SNI.

### DoQ Server (`doq-server.rs`)

A basic DoQ server that responds to DNS queries. This example server returns NXDOMAIN for all queries.

```bash
# Build the example
cargo build --example doq-server --features doq

# Run the server on default port (853)
cargo run --example doq-server --features doq

# Run on a custom address/port
cargo run --example doq-server --features doq -- 127.0.0.1:8853
```

### Zone Transfer Client (`doq-zone-transfer.rs`)

Demonstrates DNS AXFR zone transfers over DoQ.

```bash
# Build the example
cargo build --example doq-zone-transfer --features doq

# Perform an AXFR zone transfer
cargo run --example doq-zone-transfer --features doq -- 127.0.0.1 example.com
```

Received records are parsed incrementally and streamed to a zone file named
`<zone>.zone` (e.g. `example.com.zone`, or `root.zone` for the root zone) in the
current directory, so the full zone is written to disk without buffering the
entire transfer in memory.

## Common Module (`doq_common/`)

The `doq_common/mod.rs` module provides shared utilities for DoQ examples:

- DoQ constants (port 853, ALPN token "doq")
- DNS message parsing and serialization with 2-octet length prefix
- DoQ error codes as specified in [RFC 9250](https://datatracker.ietf.org/doc/html/rfc9250#section-4.3)
- DNS query building utilities
- Helper functions for DNS message manipulation

## Key Implementation Details

### RFC 9250 Compliance

The implementation follows these key requirements from [RFC 9250](https://datatracker.ietf.org/doc/html/rfc9250):

1. **ALPN Token**: Uses "doq" for Application-Layer Protocol Negotiation
2. **Default Port**: UDP port 853 (not 53)
3. **Stream Mapping**: Each DNS query uses a separate bidirectional QUIC stream
4. **Message Format**: 2-octet length field followed by DNS message (same as DNS-over-TCP)
5. **Message ID**: Always set to 0 for DoQ messages
6. **0-RTT Support**: Only QUERY and NOTIFY opcodes allowed in 0-RTT data
7. **Error Codes**: Implements DoQ-specific error codes (0x0-0x5 and 0xd098ea5e)

### Security Considerations

- **Certificate Validation**: The examples disable certificate validation for testing. Production deployments MUST enable proper certificate validation.
- **0-RTT Replay Protection**: The server example validates opcodes in 0-RTT data to prevent replay attacks.
- **Padding**: Consider implementing padding (EDNS0 or QUIC-level) for privacy protection.

### Performance Considerations

- **Connection Reuse**: Clients should reuse connections for multiple queries
- **Concurrent Streams**: Multiple DNS queries can be sent in parallel on different streams
- **Flow Control**: Larger limits are configured for zone transfers

## Testing

Run the DoQ unit tests (covering wire format, error codes, and the
0-RTT replayable-opcode helper):

```bash
cargo test --features doq --workspace --lib -- doq
```

## Production Deployment

For production use, consider:

1. Implementing proper DNS response generation (the server example only returns NXDOMAIN)
2. Adding comprehensive DNS parsing and validation
3. Implementing proper logging and monitoring
4. Adding rate limiting and DDoS protection
5. Configuring appropriate idle timeouts and flow control limits
6. Implementing DNS caching where appropriate
7. Adding support for EDNS0 options
8. Implementing proper padding for privacy

## References

- [RFC 9250 - DNS over Dedicated QUIC Connections](https://datatracker.ietf.org/doc/html/rfc9250)
- [RFC 1035 - Domain Names - Implementation and Specification](https://datatracker.ietf.org/doc/html/rfc1035)
- [RFC 7858 - DNS over TLS](https://datatracker.ietf.org/doc/html/rfc7858)
