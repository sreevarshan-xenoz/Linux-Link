use linux_link_core::protocol::kdeconnect::Plugin;

#[derive(Debug, Default)]
pub struct ClipboardPlugin;

impl ClipboardPlugin {
    pub fn new() -> Self {
        Self
    }
}

impl Plugin for ClipboardPlugin {
    fn name(&self) -> &'static str {
        "clipboard"
    }

    fn incoming_capabilities(&self) -> &'static [&'static str] {
        &["kdeconnect.clipboard", "kdeconnect.clipboard.connect"]
    }

    fn outgoing_capabilities(&self) -> &'static [&'static str] {
        &["kdeconnect.clipboard"]
    }
}
