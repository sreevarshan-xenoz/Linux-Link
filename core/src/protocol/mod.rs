pub mod connection;
pub mod kdeconnect;

#[cfg(test)]
mod kdeconnect_test;

pub const HANDSHAKE_HELLO: &str = "LINUX_LINK_HELLO 1";
pub const HANDSHAKE_OK: &str = "LINUX_LINK_OK 1";
