use anyhow::{Context, Result};
use std::net::UdpSocket;

/// Send a Wake-on-LAN magic packet to the specified MAC address.
///
/// The magic packet consists of 6 bytes of 0xFF followed by the MAC address
/// repeated 16 times, sent as a UDP broadcast on port 9.
pub fn send_wol(mac_address: &str, broadcast_addr: &str) -> Result<()> {
    let mac = parse_mac(mac_address).context("Failed to parse MAC address")?;

    // Build magic packet: 6 bytes of 0xFF + MAC repeated 16 times
    let mut packet = Vec::with_capacity(6 + 16 * 6);
    packet.extend_from_slice(&[0xFF; 6]);
    for _ in 0..16 {
        packet.extend_from_slice(&mac);
    }

    let socket = UdpSocket::bind("0.0.0.0:0").context("Failed to bind UDP socket for WOL")?;
    socket
        .set_broadcast(true)
        .context("Failed to enable broadcast on WOL socket")?;

    let addr = format!("{}:9", broadcast_addr);
    let sent = socket
        .send_to(&packet, &addr)
        .context("Failed to send WOL magic packet")?;

    tracing::info!("Sent WOL magic packet to {addr} ({sent} bytes, MAC: {mac_address})");
    Ok(())
}

/// Send WOL to the broadcast address with automatic retries.
pub fn send_wol_with_retry(mac_address: &str, broadcast_addr: &str, retries: u32) -> Result<()> {
    for attempt in 1..=retries {
        if attempt > 1 {
            std::thread::sleep(std::time::Duration::from_millis(500));
        }
        match send_wol(mac_address, broadcast_addr) {
            Ok(()) => return Ok(()),
            Err(e) => {
                tracing::warn!("WOL attempt {attempt}/{retries} failed: {e}");
                if attempt == retries {
                    return Err(e).context("All WOL retries exhausted");
                }
            }
        }
    }
    Ok(())
}

/// Parse a MAC address string (e.g., "AA:BB:CC:DD:EE:FF" or "aa-bb-cc-dd-ee-ff")
/// into a 6-byte array.
fn parse_mac(mac: &str) -> Result<[u8; 6]> {
    let clean: String = mac
        .chars()
        .filter(|c| c.is_ascii_hexdigit() || *c == ':')
        .collect();
    let hex: String = clean.chars().filter(|c| c.is_ascii_hexdigit()).collect();

    if hex.len() != 12 {
        anyhow::bail!(
            "Invalid MAC address: expected 12 hex digits, got {} from '{}'",
            hex.len(),
            mac
        );
    }

    let mut bytes = [0u8; 6];
    for i in 0..6 {
        bytes[i] = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16)
            .context(format!("Failed to parse hex byte at position {}", i))?;
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_mac_colon() {
        let mac = parse_mac("AA:BB:CC:DD:EE:FF").unwrap();
        assert_eq!(mac, [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
    }

    #[test]
    fn test_parse_mac_hyphen() {
        let mac = parse_mac("aa-bb-cc-dd-ee-ff").unwrap();
        assert_eq!(mac, [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
    }

    #[test]
    fn test_parse_mac_lowercase() {
        let mac = parse_mac("a1:b2:c3:d4:e5:f6").unwrap();
        assert_eq!(mac, [0xA1, 0xB2, 0xC3, 0xD4, 0xE5, 0xF6]);
    }

    #[test]
    fn test_parse_mac_invalid() {
        assert!(parse_mac("not-a-mac").is_err());
        assert!(parse_mac("AA:BB:CC:DD:EE").is_err());
    }

    #[test]
    fn test_parse_mac_no_separator() {
        let mac = parse_mac("AABBCCDDEEFF").unwrap();
        assert_eq!(mac, [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
    }

    #[test]
    fn test_magic_packet_size() {
        let mac = parse_mac("00:11:22:33:44:55").unwrap();
        let mut packet = Vec::with_capacity(6 + 16 * 6);
        packet.extend_from_slice(&[0xFF; 6]);
        for _ in 0..16 {
            packet.extend_from_slice(&mac);
        }
        assert_eq!(packet.len(), 102);
        assert_eq!(packet[0..6], [0xFF; 6]);
        // Each of the 16 repetitions should match the MAC
        for i in 0..16 {
            let start = 6 + i * 6;
            assert_eq!(packet[start..start + 6], mac, "Repetition {i} mismatch");
        }
    }
}
