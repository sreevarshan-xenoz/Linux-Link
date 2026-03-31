use linux_link_core::protocol::kdeconnect::Plugin;

#[derive(Debug, Default)]
pub struct NotificationPlugin;

impl NotificationPlugin {
    pub fn new() -> Self {
        Self
    }
}

impl Plugin for NotificationPlugin {
    fn name(&self) -> &'static str {
        "notification"
    }

    fn incoming_capabilities(&self) -> &'static [&'static str] {
        &["kdeconnect.notification", "kdeconnect.notification.request"]
    }

    fn outgoing_capabilities(&self) -> &'static [&'static str] {
        &["kdeconnect.notification"]
    }
}
