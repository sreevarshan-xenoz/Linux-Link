pub mod battery;
pub mod clipboard;
pub mod exec;
pub mod file_browse;
pub mod input;
pub mod monitors;
pub mod notification;
pub mod power;
pub mod share;

use linux_link_core::protocol::kdeconnect::PluginRegistry;

/// Shorthand for the full plugin registry type with all 9 plugins registered.
pub type PluginSet = PluginRegistry;

/// Register all 9 KDE Connect plugins and return the registry.
pub fn register_all() -> PluginSet {
    let mut registry = PluginRegistry::new();
    registry.register(battery::BatteryPlugin::new());
    registry.register(clipboard::ClipboardPlugin::new());
    registry.register(notification::NotificationPlugin::new());
    registry.register(share::SharePlugin::new());
    registry.register(input::InputPlugin::new());
    registry.register(file_browse::FileBrowsePlugin::new());
    registry.register(power::PowerPlugin::new());
    registry.register(exec::ExecPlugin::new());
    registry.register(monitors::MonitorsPlugin);
    registry
}
