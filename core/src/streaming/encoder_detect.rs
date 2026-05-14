//! Hardware encoder detection for cross-platform video encoding.
//!
//! Probes the system for available hardware-accelerated encoders
//! (VAAPI, NVENC) and falls back to software encoding (libx264).
//! Uses `ffmpeg-sidecar` to enumerate available encoders.

use serde::{Deserialize, Serialize};
use std::process::Command;
use tracing::{debug, info, warn};

/// Available hardware encoder backends.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum HardwareEncoder {
    /// Auto-detect the best available encoder
    #[default]
    Auto,
    /// VAAPI (Intel/AMD GPUs on Linux)
    Vaapi,
    /// NVENC (NVIDIA GPUs)
    Nvenc,
    /// Software encoding via libx264
    Software,
}

impl HardwareEncoder {
    /// Human-readable name
    pub fn display_name(&self) -> &'static str {
        match self {
            HardwareEncoder::Auto => "Auto-detect",
            HardwareEncoder::Vaapi => "VAAPI (Intel/AMD)",
            HardwareEncoder::Nvenc => "NVENC (NVIDIA)",
            HardwareEncoder::Software => "Software (libx264)",
        }
    }

    /// FFmpeg encoder name for this selection and codec.
    /// Returns both the encoder name and whether it supports HEVC.
    pub fn supports_hevc(&self) -> bool {
        match self {
            HardwareEncoder::Vaapi => true,
            HardwareEncoder::Nvenc => true,
            HardwareEncoder::Auto | HardwareEncoder::Software => true, // libx265
        }
    }

    /// FFmpeg encoder name for H.264 encoding
    pub fn ffmpeg_encoder(&self) -> &'static str {
        match self {
            HardwareEncoder::Auto | HardwareEncoder::Software => "libx264",
            HardwareEncoder::Vaapi => "h264_vaapi",
            HardwareEncoder::Nvenc => "h264_nvenc",
        }
    }

    /// FFmpeg encoder name for HEVC encoding
    pub fn ffmpeg_encoder_hevc(&self) -> &'static str {
        match self {
            HardwareEncoder::Auto | HardwareEncoder::Software => "libx265",
            HardwareEncoder::Vaapi => "hevc_vaapi",
            HardwareEncoder::Nvenc => "hevc_nvenc",
        }
    }
}

/// Result of probing system for available encoders.
#[derive(Debug, Clone)]
pub struct AvailableEncoders {
    pub vaapi: bool,
    pub nvenc: bool,
    pub software: bool,
}

/// Probe the system for available hardware encoders.
///
/// Runs `ffmpeg -encoders` and parses the output to check for
/// VAAPI and NVENC encoders (both H.264 and HEVC variants).
/// Always reports software as available.
pub fn probe_encoders() -> AvailableEncoders {
    let mut available = AvailableEncoders {
        vaapi: false,
        nvenc: false,
        software: true,
    };

    // Run ffmpeg -encoders to enumerate available encoders
    let output = match Command::new("ffmpeg")
        .args(["-hide_banner", "-encoders"])
        .output()
    {
        Ok(output) => output,
        Err(e) => {
            warn!("Failed to run ffmpeg -encoders: {e}");
            info!("Assuming software encoding only");
            return available;
        }
    };

    let stdout = String::from_utf8_lossy(&output.stdout);

    for line in stdout.lines() {
        let trimmed = line.trim();
        // VAAPI encoders
        if trimmed.contains("h264_vaapi") || trimmed.contains("hevc_vaapi") {
            available.vaapi = true;
            debug!("Detected VAAPI encoder: {trimmed}");
        }
        // NVENC encoders
        if trimmed.contains("h264_nvenc") || trimmed.contains("hevc_nvenc") {
            available.nvenc = true;
            debug!("Detected NVENC encoder: {trimmed}");
        }
    }

    if !available.vaapi && !available.nvenc {
        info!("No hardware encoder detected, using software encoding");
    } else {
        info!(
            "Hardware encoders available: VAAPI={}, NVENC={}",
            available.vaapi, available.nvenc
        );
    }

    available
}

/// Resolve the `HardwareEncoder` selection to the actual encoder to use,
/// falling back through the chain if the selected encoder is not available.
pub fn resolve_encoder(
    selected: HardwareEncoder,
    available: &AvailableEncoders,
) -> HardwareEncoder {
    match selected {
        HardwareEncoder::Auto => {
            if available.nvenc {
                info!("Auto-detect: selecting NVENC");
                HardwareEncoder::Nvenc
            } else if available.vaapi {
                info!("Auto-detect: selecting VAAPI");
                HardwareEncoder::Vaapi
            } else {
                info!("Auto-detect: no hardware encoder, using software");
                HardwareEncoder::Software
            }
        }
        HardwareEncoder::Vaapi if !available.vaapi => {
            warn!("VAAPI selected but not available, falling back to software");
            HardwareEncoder::Software
        }
        HardwareEncoder::Nvenc if !available.nvenc => {
            warn!("NVENC selected but not available, falling back to software");
            HardwareEncoder::Software
        }
        other => other,
    }
}

/// Build the FFmpeg encoder argument for the given hardware encoder
/// and resolution. Some encoders require additional flags (e.g., VAAPI
/// requires a device selection).
pub fn encoder_args(hw_encoder: &HardwareEncoder, width: u32, height: u32) -> Vec<String> {
    match hw_encoder {
        HardwareEncoder::Vaapi => {
            vec![
                "-vaapi_device".to_string(),
                "/dev/dri/renderD128".to_string(), // Default VAAPI device
                "-c:v".to_string(),
                "h264_vaapi".to_string(),
                "-vf".to_string(),
                format!("format=nv12,hwupload,scale_vaapi=w={}:h={}", width, height),
            ]
        }
        HardwareEncoder::Nvenc => {
            vec![
                "-c:v".to_string(),
                "h264_nvenc".to_string(),
                "-preset".to_string(),
                "p1".to_string(), // Fastest NVENC preset
                "-rc".to_string(),
                "vbr".to_string(),
            ]
        }
        HardwareEncoder::Auto | HardwareEncoder::Software => {
            vec![
                "-c:v".to_string(),
                "libx264".to_string(),
                "-preset".to_string(),
                "ultrafast".to_string(),
                "-tune".to_string(),
                "zerolatency".to_string(),
            ]
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hardware_encoder_display_names() {
        assert_eq!(HardwareEncoder::Auto.display_name(), "Auto-detect");
        assert_eq!(HardwareEncoder::Vaapi.display_name(), "VAAPI (Intel/AMD)");
        assert_eq!(HardwareEncoder::Nvenc.display_name(), "NVENC (NVIDIA)");
        assert_eq!(
            HardwareEncoder::Software.display_name(),
            "Software (libx264)"
        );
    }

    #[test]
    fn test_ffmpeg_encoder_names() {
        assert_eq!(HardwareEncoder::Auto.ffmpeg_encoder(), "libx264");
        assert_eq!(HardwareEncoder::Vaapi.ffmpeg_encoder(), "h264_vaapi");
        assert_eq!(HardwareEncoder::Nvenc.ffmpeg_encoder(), "h264_nvenc");
        assert_eq!(HardwareEncoder::Software.ffmpeg_encoder(), "libx264");
    }

    #[test]
    fn test_resolve_auto_with_nvenc() {
        let available = AvailableEncoders {
            vaapi: false,
            nvenc: true,
            software: true,
        };
        assert_eq!(
            resolve_encoder(HardwareEncoder::Auto, &available),
            HardwareEncoder::Nvenc
        );
    }

    #[test]
    fn test_resolve_auto_with_vaapi() {
        let available = AvailableEncoders {
            vaapi: true,
            nvenc: false,
            software: true,
        };
        assert_eq!(
            resolve_encoder(HardwareEncoder::Auto, &available),
            HardwareEncoder::Vaapi
        );
    }

    #[test]
    fn test_resolve_auto_software_only() {
        let available = AvailableEncoders {
            vaapi: false,
            nvenc: false,
            software: true,
        };
        assert_eq!(
            resolve_encoder(HardwareEncoder::Auto, &available),
            HardwareEncoder::Software
        );
    }

    #[test]
    fn test_resolve_vaapi_fallback() {
        let available = AvailableEncoders {
            vaapi: false,
            nvenc: false,
            software: true,
        };
        assert_eq!(
            resolve_encoder(HardwareEncoder::Vaapi, &available),
            HardwareEncoder::Software
        );
    }

    #[test]
    fn test_resolve_nvenc_stays() {
        let available = AvailableEncoders {
            vaapi: false,
            nvenc: true,
            software: true,
        };
        assert_eq!(
            resolve_encoder(HardwareEncoder::Nvenc, &available),
            HardwareEncoder::Nvenc
        );
    }

    #[test]
    fn test_encoder_args_vaapi() {
        let args = encoder_args(&HardwareEncoder::Vaapi, 1920, 1080);
        assert!(args.contains(&"-vaapi_device".to_string()));
        assert!(args.contains(&"h264_vaapi".to_string()));
        assert!(args.contains(&"format=nv12,hwupload,scale_vaapi=w=1920:h=1080".to_string()));
    }

    #[test]
    fn test_encoder_args_nvenc() {
        let args = encoder_args(&HardwareEncoder::Nvenc, 1280, 720);
        assert!(args.contains(&"h264_nvenc".to_string()));
        assert!(args.contains(&"p1".to_string()));
    }

    #[test]
    fn test_encoder_args_software() {
        let args = encoder_args(&HardwareEncoder::Software, 1920, 1080);
        assert!(args.contains(&"libx264".to_string()));
        assert!(args.contains(&"ultrafast".to_string()));
    }
}
