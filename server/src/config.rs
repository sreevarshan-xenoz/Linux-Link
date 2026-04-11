use anyhow::{Context, Result};
use linux_link_core::DEFAULT_CONTROL_PORT;
use linux_link_core::streaming::VideoQualityPreset;
use linux_link_core::streaming::client::DEFAULT_STREAMING_PORT;
use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
#[allow(dead_code)]
pub struct Config {
    #[serde(default = "default_control_port")]
    pub control_port: u16,
    #[serde(default = "default_streaming_port")]
    pub streaming_port: u16,
    #[serde(default = "default_log_level")]
    pub log_level: String,
    #[serde(default)]
    pub video_quality: VideoQualityPreset,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            control_port: DEFAULT_CONTROL_PORT,
            streaming_port: DEFAULT_STREAMING_PORT,
            log_level: "info".to_string(),
            video_quality: VideoQualityPreset::Balanced,
        }
    }
}

impl Config {
    pub fn load() -> Result<Self> {
        let config_path = dirs::config_dir()
            .context("unable to determine config directory")?
            .join("linux-link")
            .join("config.toml");

        if !config_path.exists() {
            return Ok(Self::default());
        }

        let raw = std::fs::read_to_string(&config_path)
            .with_context(|| format!("failed reading {}", config_path.display()))?;
        let parsed: Self = toml::from_str(&raw)
            .with_context(|| format!("invalid TOML in {}", config_path.display()))?;
        Ok(parsed)
    }
}

const fn default_control_port() -> u16 {
    DEFAULT_CONTROL_PORT
}

const fn default_streaming_port() -> u16 {
    DEFAULT_STREAMING_PORT
}

fn default_log_level() -> String {
    "info".to_string()
}
