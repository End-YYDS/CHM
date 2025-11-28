use chm_grpc::restful;
use std::convert::TryFrom;

use crate::handles::info::types::{
    ClusterSummary, GetAllInfoResponse, InfoCounts, InfoGetResponse, PcMetrics, StatusLabel, Target,
};
impl From<restful::InfoCounts> for InfoCounts {
    fn from(value: restful::InfoCounts) -> Self {
        Self { safe: value.safe, warn: value.warn, dang: value.dang }
    }
}

impl From<restful::ClusterSummary> for ClusterSummary {
    fn from(value: restful::ClusterSummary) -> Self {
        Self { cpu: value.cpu, memory: value.memory, disk: value.disk }
    }
}

impl From<restful::PcMetrics> for PcMetrics {
    fn from(value: restful::PcMetrics) -> Self {
        fn convert_status(raw: i32) -> StatusLabel {
            let status = restful::InfoStatus::try_from(raw).unwrap_or(restful::InfoStatus::Unknown);
            match status {
                restful::InfoStatus::Safe => StatusLabel::Safe,
                restful::InfoStatus::Warn => StatusLabel::Warn,
                restful::InfoStatus::Dang => StatusLabel::Dang,
                restful::InfoStatus::Unknown | restful::InfoStatus::Unspecified => {
                    StatusLabel::Unknown
                }
            }
        }
        Self {
            cpu:         value.cpu,
            memory:      value.memory,
            disk:        value.disk,
            cpu_status:  convert_status(value.cpu_status),
            mem_status:  convert_status(value.memory_status),
            disk_status: convert_status(value.disk_status),
        }
    }
}

impl From<restful::GetAllInfoResponse> for GetAllInfoResponse {
    fn from(resp: restful::GetAllInfoResponse) -> Self {
        Self {
            info:    resp.info.map(InfoCounts::from).unwrap_or_default(),
            cluster: resp.cluster.map(ClusterSummary::from).unwrap_or_default(),
        }
    }
}

impl From<restful::GetInfoResponse> for InfoGetResponse {
    fn from(resp: restful::GetInfoResponse) -> Self {
        let pcs = resp.pcs.into_iter().map(|(k, v)| (k, PcMetrics::from(v))).collect();
        Self { pcs, length: resp.length as usize }
    }
}

impl From<Target> for restful::Target {
    fn from(value: Target) -> Self {
        match value {
            Target::Safe => restful::Target::Safe,
            Target::Warn => restful::Target::Warn,
            Target::Dang => restful::Target::Dang,
        }
    }
}
