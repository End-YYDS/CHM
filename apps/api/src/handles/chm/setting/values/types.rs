use chm_grpc::restful;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone, Copy, Default)]
pub struct MetricSetting {
    #[serde(rename = "Warn", default)]
    pub warn: f64,
    #[serde(rename = "Dang", default)]
    pub dang: f64,
}

impl From<restful::MetricSetting> for MetricSetting {
    fn from(value: restful::MetricSetting) -> Self {
        Self { warn: value.warn, dang: value.dang }
    }
}

impl From<MetricSetting> for restful::MetricSetting {
    fn from(value: MetricSetting) -> Self {
        restful::MetricSetting { warn: value.warn, dang: value.dang }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone, Copy, Default)]
pub struct Values {
    #[serde(rename = "Cpu_usage", default)]
    pub cpu_usage:  MetricSetting,
    #[serde(rename = "Disk_usage", default)]
    pub disk_usage: MetricSetting,
    #[serde(rename = "Memory", default)]
    pub memory:     MetricSetting,
}

impl From<restful::Values> for Values {
    fn from(value: restful::Values) -> Self {
        Self {
            cpu_usage:  value.cpu_usage.map(MetricSetting::from).unwrap_or_default(),
            disk_usage: value.disk_usage.map(MetricSetting::from).unwrap_or_default(),
            memory:     value.memory.map(MetricSetting::from).unwrap_or_default(),
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct ValuesUpdate {
    #[serde(rename = "Cpu_usage")]
    pub cpu_usage:  Option<MetricSetting>,
    #[serde(rename = "Disk_usage")]
    pub disk_usage: Option<MetricSetting>,
    #[serde(rename = "Memory")]
    pub memory:     Option<MetricSetting>,
}

impl ValuesUpdate {
    pub fn into_grpc(self) -> restful::PutSettingValuesRequest {
        restful::PutSettingValuesRequest {
            cpu_usage:  self.cpu_usage.map(restful::MetricSetting::from),
            disk_usage: self.disk_usage.map(restful::MetricSetting::from),
            memory:     self.memory.map(restful::MetricSetting::from),
        }
    }
}
