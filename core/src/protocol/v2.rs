use serde::{Deserialize, Serialize};

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
