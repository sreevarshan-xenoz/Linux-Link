use linux_link_core::protocol::kdeconnect::Plugin;

#[derive(Debug, Default)]
pub struct SharePlugin;

impl SharePlugin {
    pub fn new() -> Self {
        Self
    }
}

impl Plugin for SharePlugin {
    fn name(&self) -> &'static str {
        "share"
    }

    fn incoming_capabilities(&self) -> &'static [&'static str] {
        &["kdeconnect.share.request"]
    }

    fn outgoing_capabilities(&self) -> &'static [&'static str] {
        &["kdeconnect.share.request"]
    }
}
