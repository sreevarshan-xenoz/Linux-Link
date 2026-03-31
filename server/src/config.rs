use anyhow::{Context, Result};
use linux_link_core::DEFAULT_CONTROL_PORT;
use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    #[serde(default = "default_control_port")]
    pub control_port: u16,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            control_port: DEFAULT_CONTROL_PORT,
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
