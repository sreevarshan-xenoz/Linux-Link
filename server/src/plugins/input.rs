use linux_link_core::protocol::kdeconnect::Plugin;

#[derive(Debug, Default)]
pub struct InputPlugin;

impl InputPlugin {
    pub fn new() -> Self {
        Self
    }
}

impl Plugin for InputPlugin {
    fn name(&self) -> &'static str {
        "input"
    }

    fn incoming_capabilities(&self) -> &'static [&'static str] {
        &["kdeconnect.mousepad.request", "kdeconnect.presenter"]
    }

    fn outgoing_capabilities(&self) -> &'static [&'static str] {
        &["kdeconnect.mousepad.echo"]
    }
}
