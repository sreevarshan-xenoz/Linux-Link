//! Linux Link Android Rust backend scaffold.

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConnectionState {
    Connected,
    Disconnected,
    Connecting,
    Error(String),
}

pub fn version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}

pub async fn connect(_address: String) -> Result<ConnectionState, String> {
    Ok(ConnectionState::Disconnected)
}
