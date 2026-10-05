use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BioTemplate {
    pub id: Vec<u8>,
    pub name: Option<String>,
}

impl BioTemplate {
    pub fn id_hex(&self) -> String {
        crate::model::to_hex(&self.id)
    }

    pub fn display_name(&self) -> String {
        match &self.name {
            Some(n) if !n.is_empty() => n.clone(),
            _ => format!("Fingerprint {}", self.id_hex()),
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct BioSensorInfo {
    /// 1 = touch sensor, 2 = swipe sensor
    pub sensor_type: u8,
    pub max_samples: u8,
}

impl BioSensorInfo {
    pub fn sensor_label(&self) -> &'static str {
        match self.sensor_type {
            1 => "touch",
            2 => "swipe",
            _ => "unknown",
        }
    }
}

/// Feedback for a single fingerprint capture during enrollment.
pub fn bio_sample_feedback(status: u8) -> &'static str {
    match status {
        0x00 => "Good sample",
        0x01 => "Finger too high",
        0x02 => "Finger too low",
        0x03 => "Finger too far left",
        0x04 => "Finger too far right",
        0x05 => "Too fast",
        0x06 => "Too slow",
        0x07 => "Poor quality",
        0x08 => "Finger skewed",
        0x09 => "Too short",
        0x0a => "Merge failure",
        0x0b => "Fingerprint already enrolled",
        0x0c => "Fingerprint storage full",
        0x0d => "No finger detected",
        0x0e => "Lift and place your finger again",
        _ => "Unknown sample status",
    }
}
