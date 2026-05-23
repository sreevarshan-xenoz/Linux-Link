use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::error::Result;

pub const ALPN_V2: &[u8] = b"linux-link-v2";

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

    let mut buf = vec![0u8; len];
    recv.read_exact(&mut buf).await?;

    Ok(serde_json::from_slice(&buf)?)
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
