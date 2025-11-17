use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone, Copy)]
pub struct Values {
    #[serde(rename = "Cpu_usage", default)]
    pub cpu_usage:  f64,
    #[serde(rename = "Disk_usage", default)]
    pub disk_usage: f64,
    #[serde(rename = "Memory", default)]
    pub memory:     f64,
    #[serde(rename = "Network", default)]
    pub network:    f64,
}

impl Default for Values {
    fn default() -> Self {
        Self { cpu_usage: 0.0, disk_usage: 0.0, memory: 0.0, network: 0.0 }
    }
}

#[derive(Debug, Deserialize)]
pub struct ValuesUpdate {
    #[serde(rename = "Cpu_usage")]
    pub cpu_usage:  Option<f64>,
    #[serde(rename = "Disk_usage")]
    pub disk_usage: Option<f64>,
    #[serde(rename = "Memory")]
    pub memory:     Option<f64>,
    #[serde(rename = "Network")]
    pub network:    Option<f64>,
}
