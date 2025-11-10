// Copyright (C) 2024, Cloudflare, Inc.
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:
//
//     * Redistributions of source code must retain the above copyright notice,
//       this list of conditions and the following disclaimer.
//

#![cfg(feature = "doq")]
//     * Redistributions in binary form must reproduce the above copyright
//       notice, this list of conditions and the following disclaimer in the
//       documentation and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
// IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
// THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
// PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR
// CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
// EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
// PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
// LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
// NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
// SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

#[cfg(test)]
mod doq_tests {
    use std::io::Write;

    // Include DoQ constants and types for testing
    pub const DOQ_PORT: u16 = 853;
    pub const DOQ_ALPN: &[u8] = b"doq";

    #[derive(Debug, Clone, Copy, PartialEq)]
    #[repr(u64)]
    pub enum DoqError {
        NoError = 0x0,
        InternalError = 0x1,
        ProtocolError = 0x2,
        RequestCancelled = 0x3,
        ExcessiveLoad = 0x4,
        UnspecifiedError = 0x5,
        ErrorReserved = 0xd098ea5e,
    }

    impl DoqError {
        pub fn to_wire(self) -> u64 {
            self as u64
        }
    }

    pub const REPLAYABLE_OPCODES: &[u8] = &[0, 4];

    pub fn is_replayable_opcode(opcode: u8) -> bool {
        REPLAYABLE_OPCODES.contains(&opcode)
    }

    pub fn parse_dns_message(data: &[u8]) -> Result<(&[u8], usize), String> {
        if data.len() < 2 {
            return Err("Insufficient data for length field".to_string());
        }
        
        let length = u16::from_be_bytes([data[0], data[1]]) as usize;
        
        if data.len() < 2 + length {
            return Err(format!(
                "Insufficient data for DNS message: expected {}, got {}",
                length,
                data.len() - 2
            ));
        }
        
        Ok((&data[2..2 + length], 2 + length))
    }

    pub fn write_dns_message<W: Write>(writer: &mut W, dns_data: &[u8]) -> Result<(), std::io::Error> {
        if dns_data.len() > 65535 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "DNS message too large",
            ));
        }
        
        let length = (dns_data.len() as u16).to_be_bytes();
        writer.write_all(&length)?;
        writer.write_all(dns_data)?;
        Ok(())
    }

    pub fn get_dns_opcode(dns_msg: &[u8]) -> Result<u8, String> {
        if dns_msg.len() < 12 {
            return Err("DNS message too short".to_string());
        }
        
        let flags = u16::from_be_bytes([dns_msg[2], dns_msg[3]]);
        Ok(((flags >> 11) & 0x0F) as u8)
    }

    pub fn set_dns_id_zero(dns_msg: &mut [u8]) -> Result<(), String> {
        if dns_msg.len() < 2 {
            return Err("DNS message too short".to_string());
        }
        
        dns_msg[0] = 0;
        dns_msg[1] = 0;
        Ok(())
    }

    pub fn get_dns_id(dns_msg: &[u8]) -> Result<u16, String> {
        if dns_msg.len() < 2 {
            return Err("DNS message too short".to_string());
        }
        
        Ok(u16::from_be_bytes([dns_msg[0], dns_msg[1]]))
    }

    pub struct DnsQueryBuilder {
        buffer: Vec<u8>,
    }

    impl DnsQueryBuilder {
        pub fn new() -> Self {
            Self {
                buffer: vec![0; 12],
            }
        }
        
        pub fn build_query(mut self, domain: &str, qtype: QueryType) -> Result<Vec<u8>, String> {
            self.buffer[0] = 0;
            self.buffer[1] = 0;
            self.buffer[2] = 0x01;
            self.buffer[3] = 0x00;
            self.buffer[4] = 0;
            self.buffer[5] = 1;
            
            for i in 6..12 {
                self.buffer[i] = 0;
            }
            
            self.encode_domain_name(domain)?;
            self.buffer.extend_from_slice(&(qtype as u16).to_be_bytes());
            self.buffer.extend_from_slice(&1u16.to_be_bytes());
            
            Ok(self.buffer)
        }
        
        fn encode_domain_name(&mut self, domain: &str) -> Result<(), String> {
            for label in domain.split('.') {
                if label.is_empty() {
                    continue;
                }
                
                if label.len() > 63 {
                    return Err("Label too long".to_string());
                }
                
                self.buffer.push(label.len() as u8);
                self.buffer.extend_from_slice(label.as_bytes());
            }
            
            self.buffer.push(0);
            Ok(())
        }
    }

    #[derive(Debug, Clone, Copy)]
    #[repr(u16)]
    pub enum QueryType {
        A = 1,
    }

    pub fn parse_dns_response_header(dns_msg: &[u8]) -> Result<DnsHeader, String> {
        if dns_msg.len() < 12 {
            return Err("DNS message too short for header".to_string());
        }
        
        let id = u16::from_be_bytes([dns_msg[0], dns_msg[1]]);
        let flags = u16::from_be_bytes([dns_msg[2], dns_msg[3]]);
        let qdcount = u16::from_be_bytes([dns_msg[4], dns_msg[5]]);
        let ancount = u16::from_be_bytes([dns_msg[6], dns_msg[7]]);
        let nscount = u16::from_be_bytes([dns_msg[8], dns_msg[9]]);
        let arcount = u16::from_be_bytes([dns_msg[10], dns_msg[11]]);
        
        Ok(DnsHeader {
            id,
            flags,
            qdcount,
            ancount,
            nscount,
            arcount,
        })
    }

    #[derive(Debug)]
    pub struct DnsHeader {
        pub id: u16,
        pub flags: u16,
        pub qdcount: u16,
        pub ancount: u16,
        pub nscount: u16,
        pub arcount: u16,
    }

    impl DnsHeader {
        pub fn is_response(&self) -> bool {
            (self.flags & 0x8000) != 0
        }
    }

    pub fn format_rcode(rcode: u8) -> &'static str {
        match rcode {
            0 => "NOERROR",
            1 => "FORMERR",
            2 => "SERVFAIL",
            3 => "NXDOMAIN",
            4 => "NOTIMP",
            5 => "REFUSED",
            _ => "UNKNOWN",
        }
    }

    // Tests
    #[test]
    fn test_dns_message_parsing() {
        let data = vec![
            0x00, 0x0C, // Length: 12 bytes
            0x00, 0x00, // ID: 0
            0x01, 0x00, // Flags: RD=1
            0x00, 0x01, // QDCOUNT: 1
            0x00, 0x00, // ANCOUNT: 0
            0x00, 0x00, // NSCOUNT: 0
            0x00, 0x00, // ARCOUNT: 0
        ];

        let (msg, consumed) = parse_dns_message(&data).unwrap();
        assert_eq!(msg.len(), 12);
        assert_eq!(consumed, 14);
        assert_eq!(get_dns_id(msg).unwrap(), 0);
    }

    #[test]
    fn test_dns_message_writing() {
        let dns_data = vec![0x00, 0x00, 0x01, 0x00, 0x00, 0x01];
        let mut output = Vec::new();
        
        write_dns_message(&mut output, &dns_data).unwrap();
        
        assert_eq!(output.len(), 8); // 2 bytes length + 6 bytes data
        assert_eq!(output[0], 0x00);
        assert_eq!(output[1], 0x06);
        assert_eq!(&output[2..], &dns_data[..]);
    }

    #[test]
    fn test_dns_id_operations() {
        let mut dns_msg = vec![
            0x12, 0x34, // ID: 0x1234
            0x01, 0x00, // Flags
            0x00, 0x01, // QDCOUNT
            0x00, 0x00, // ANCOUNT
            0x00, 0x00, // NSCOUNT
            0x00, 0x00, // ARCOUNT
        ];

        assert_eq!(get_dns_id(&dns_msg).unwrap(), 0x1234);
        
        set_dns_id_zero(&mut dns_msg).unwrap();
        assert_eq!(get_dns_id(&dns_msg).unwrap(), 0);
    }

    #[test]
    fn test_dns_opcode_extraction() {
        let dns_msg = vec![
            0x00, 0x00, // ID
            0x28, 0x00, // Flags: Opcode=5 (UPDATE)
            0x00, 0x00, // QDCOUNT
            0x00, 0x00, // ANCOUNT
            0x00, 0x00, // NSCOUNT
            0x00, 0x00, // ARCOUNT
        ];

        assert_eq!(get_dns_opcode(&dns_msg).unwrap(), 5);
    }

    #[test]
    fn test_replayable_opcodes() {
        assert!(is_replayable_opcode(0)); // QUERY
        assert!(is_replayable_opcode(4)); // NOTIFY
        assert!(!is_replayable_opcode(5)); // UPDATE
        assert!(!is_replayable_opcode(6)); // DSO
    }

    #[test]
    fn test_dns_query_builder() {
        let query = DnsQueryBuilder::new()
            .build_query("example.com", QueryType::A)
            .unwrap();

        // Check header
        assert_eq!(get_dns_id(&query).unwrap(), 0);
        
        let header = parse_dns_response_header(&query).unwrap();
        assert_eq!(header.qdcount, 1);
        assert_eq!(header.ancount, 0);
        
        // Check that it's a query (QR=0)
        assert!(!header.is_response());
    }

    #[test]
    fn test_doq_error_codes() {
        assert_eq!(DoqError::NoError.to_wire(), 0x0);
        assert_eq!(DoqError::InternalError.to_wire(), 0x1);
        assert_eq!(DoqError::ProtocolError.to_wire(), 0x2);
        assert_eq!(DoqError::RequestCancelled.to_wire(), 0x3);
        assert_eq!(DoqError::ExcessiveLoad.to_wire(), 0x4);
        assert_eq!(DoqError::UnspecifiedError.to_wire(), 0x5);
        assert_eq!(DoqError::ErrorReserved.to_wire(), 0xd098ea5e);
    }

    #[test]
    fn test_rcode_formatting() {
        assert_eq!(format_rcode(0), "NOERROR");
        assert_eq!(format_rcode(1), "FORMERR");
        assert_eq!(format_rcode(2), "SERVFAIL");
        assert_eq!(format_rcode(3), "NXDOMAIN");
        assert_eq!(format_rcode(4), "NOTIMP");
        assert_eq!(format_rcode(5), "REFUSED");
        assert_eq!(format_rcode(99), "UNKNOWN");
    }

    #[test]
    fn test_large_dns_message() {
        let large_data = vec![0; 65535];
        let mut output = Vec::new();
        
        write_dns_message(&mut output, &large_data).unwrap();
        assert_eq!(output.len(), 65537); // 2 bytes length + 65535 bytes data
        assert_eq!(output[0], 0xFF);
        assert_eq!(output[1], 0xFF);
    }

    #[test]
    fn test_oversized_dns_message() {
        let oversized_data = vec![0; 65536];
        let mut output = Vec::new();
        
        let result = write_dns_message(&mut output, &oversized_data);
        assert!(result.is_err());
    }
}