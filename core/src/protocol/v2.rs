use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::error::{LinuxLinkError, Result};

pub const ALPN_V2: &[u8] = b"linux-link-v2";

/// Maximum size for control payloads to prevent OOM attacks.
pub const MAX_CONTROL_PAYLOAD_SIZE: usize = 16 * 1024 * 1024; // 16 MB

#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ChannelKind {
    Control = 0,
    Video = 1,
    Audio = 2,
    Input = 3,
    File = 4,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct IdentityPacketV2 {
    pub device_id: String,
    pub device_name: String,
    pub min_version: u32,
    pub max_version: u32,
    pub capabilities: Vec<String>,
}

/// Encodes `data` as JSON, prepends a 4-byte Big-Endian length, and writes to the stream.
pub async fn perform_v2_handshake(
    send: &mut quinn::SendStream,
    recv: &mut quinn::RecvStream,
    local_identity: &IdentityPacketV2,
) -> Result<IdentityPacketV2> {
    perform_v2_handshake_internal(send, recv, local_identity).await
}

/// Encodes `data` as JSON, prepends a 4-byte Big-Endian length, and writes to the stream.
pub async fn write_framed_json<T: Serialize>(
    send: &mut quinn::SendStream,
    data: &T,
) -> Result<()> {
    write_framed_json_internal(send, data).await
}

/// Reads a 4-byte BE length, then reads that many bytes into a buffer, and decodes as JSON.
pub async fn read_framed_json<T: DeserializeOwned>(
    recv: &mut quinn::RecvStream,
) -> Result<T> {
    read_framed_json_internal(recv).await
}

async fn perform_v2_handshake_internal<S, R>(
    send: &mut S,
    recv: &mut R,
    local_identity: &IdentityPacketV2,
) -> Result<IdentityPacketV2>
where
    S: AsyncWrite + Unpin,
    R: AsyncRead + Unpin,
{
    let write_fut = write_framed_json_internal(send, local_identity);
    let read_fut = read_framed_json_internal::<R, IdentityPacketV2>(recv);

    let (write_res, read_res) = tokio::join!(write_fut, read_fut);
    write_res?;
    let peer_identity = read_res?;

    if peer_identity.max_version < local_identity.min_version
        || peer_identity.min_version > local_identity.max_version
    {
        return Err(LinuxLinkError::ProtocolError {
            detail: format!(
                "Incompatible versions: local [{}-{}], peer [{}-{}]",
                local_identity.min_version,
                local_identity.max_version,
                peer_identity.min_version,
                peer_identity.max_version
            ),
        });
    }

    Ok(peer_identity)
}

async fn write_framed_json_internal<S, T>(send: &mut S, data: &T) -> Result<()>
where
    S: AsyncWrite + Unpin,
    T: Serialize,
{
    let json = serde_json::to_vec(data)?;
    let len = json.len() as u32;
    send.write_all(&len.to_be_bytes()).await?;
    send.write_all(&json).await?;
    Ok(())
}

async fn read_framed_json_internal<R, T>(recv: &mut R) -> Result<T>
where
    R: AsyncRead + Unpin,
    T: DeserializeOwned,
{
    let mut len_buf = [0u8; 4];
    recv.read_exact(&mut len_buf).await?;
    let len = u32::from_be_bytes(len_buf) as usize;

    if len > MAX_CONTROL_PAYLOAD_SIZE {
        return Err(LinuxLinkError::ProtocolError {
            detail: format!("Payload size {} exceeds limit {}", len, MAX_CONTROL_PAYLOAD_SIZE),
        });
    }

    let mut buf = vec![0u8; len];
    recv.read_exact(&mut buf).await?;

    Ok(serde_json::from_slice(&buf)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_v2_handshake_success() -> anyhow::Result<()> {
        let (mut client_recv, mut server_send) = tokio::io::duplex(1024);
        let (mut server_recv, mut client_send) = tokio::io::duplex(1024);

        let client_id = IdentityPacketV2 {
            device_id: "client".to_string(),
            device_name: "Client Device".to_string(),
            min_version: 1,
            max_version: 2,
            capabilities: vec!["cap1".to_string()],
        };

        let server_id = IdentityPacketV2 {
            device_id: "server".to_string(),
            device_name: "Server Device".to_string(),
            min_version: 2,
            max_version: 3,
            capabilities: vec!["cap2".to_string()],
        };

        let client_handshake =
            perform_v2_handshake_internal(&mut client_send, &mut client_recv, &client_id);
        let server_handshake =
            perform_v2_handshake_internal(&mut server_send, &mut server_recv, &server_id);

        let (client_res, server_res) = tokio::join!(client_handshake, server_handshake);

        let received_server_id = client_res?;
        let received_client_id = server_res?;

        assert_eq!(received_server_id.device_id, "server");
        assert_eq!(received_client_id.device_id, "client");
        assert_eq!(received_server_id.min_version, 2);
        assert_eq!(received_client_id.max_version, 2);

        Ok(())
    }

    #[tokio::test]
    async fn test_v2_handshake_version_mismatch() -> anyhow::Result<()> {
        let (mut client_recv, mut server_send) = tokio::io::duplex(1024);
        let (mut server_recv, mut client_send) = tokio::io::duplex(1024);

        let client_id = IdentityPacketV2 {
            device_id: "client".to_string(),
            device_name: "Client Device".to_string(),
            min_version: 1,
            max_version: 1,
            capabilities: vec![],
        };

        let server_id = IdentityPacketV2 {
            device_id: "server".to_string(),
            device_name: "Server Device".to_string(),
            min_version: 2,
            max_version: 2,
            capabilities: vec![],
        };

        let client_handshake =
            perform_v2_handshake_internal(&mut client_send, &mut client_recv, &client_id);
        let server_handshake =
            perform_v2_handshake_internal(&mut server_send, &mut server_recv, &server_id);

        let (client_res, server_res) = tokio::join!(client_handshake, server_handshake);

        match client_res {
            Err(LinuxLinkError::ProtocolError { detail }) => {
                assert!(detail.contains("Incompatible versions"));
            }
            _ => panic!("Expected version mismatch error, got {:?}", client_res),
        }

        match server_res {
            Err(LinuxLinkError::ProtocolError { detail }) => {
                assert!(detail.contains("Incompatible versions"));
            }
            _ => panic!("Expected version mismatch error, got {:?}", server_res),
        }

        Ok(())
    }

    #[tokio::test]
    async fn test_framed_json_roundtrip() -> anyhow::Result<()> {
        let (mut client, mut server) = tokio::io::duplex(1024);

        #[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
        struct TestPacket {
            message: String,
            count: u32,
        }

        let packet = TestPacket {
            message: "hello v2".to_string(),
            count: 42,
        };

        // Client to Server
        let client_write = write_framed_json_internal(&mut client, &packet);
        let server_read = read_framed_json_internal::<_, TestPacket>(&mut server);

        let (write_res, read_res) = tokio::join!(client_write, server_read);
        write_res?;
        let received = read_res?;
        assert_eq!(packet, received);

        // Server to Client
        let reply = TestPacket {
            message: "reply v2".to_string(),
            count: 100,
        };
        let server_write = write_framed_json_internal(&mut server, &reply);
        let client_read = read_framed_json_internal::<_, TestPacket>(&mut client);

        let (s_write_res, c_read_res) = tokio::join!(server_write, client_read);
        s_write_res?;
        let received_reply = c_read_res?;
        assert_eq!(reply, received_reply);

        Ok(())
    }

    #[tokio::test]
    async fn test_oversized_payload() -> anyhow::Result<()> {
        let (mut client, mut server) = tokio::io::duplex(1024);

        // Write a length that exceeds MAX_CONTROL_PAYLOAD_SIZE
        let oversized_len = (MAX_CONTROL_PAYLOAD_SIZE + 1) as u32;
        client.write_all(&oversized_len.to_be_bytes()).await?;

        let result = read_framed_json_internal::<_, IdentityPacketV2>(&mut server).await;
        
        match result {
            Err(LinuxLinkError::ProtocolError { detail }) => {
                assert!(detail.contains("exceeds limit"));
            }
            _ => panic!("Expected ProtocolError for oversized payload, got {:?}", result),
        }

        Ok(())
    }

    #[tokio::test]
    async fn test_malformed_json() -> anyhow::Result<()> {
        let (mut client, mut server) = tokio::io::duplex(1024);

        let malformed_data = b"{ \"not\": \"valid\" json";
        let len = malformed_data.len() as u32;
        client.write_all(&len.to_be_bytes()).await?;
        client.write_all(malformed_data).await?;

        let result = read_framed_json_internal::<_, IdentityPacketV2>(&mut server).await;

        match result {
            Err(LinuxLinkError::Serialization { format, .. }) => {
                assert_eq!(format, "JSON");
            }
            _ => panic!("Expected Serialization error for malformed JSON, got {:?}", result),
        }

        Ok(())
    }
}
