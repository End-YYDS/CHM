// Functions: get_info

use std::io;

use crate::{make_sysinfo_command, send_to_hostd, SystemInfo};

#[derive(Debug)]
pub struct AgentInfo {
    pub cpu:  f32,
    pub mem:  f32,
    pub disk: f32,
}

/// Convert HostD response into structured AgentInfo
pub async fn agent_info_structured(_sys: &SystemInfo) -> io::Result<AgentInfo> {
    let requests = ["cpu_status", "memory_status", "disk_status"];
    let mut values = Vec::new();

    for keyword in &requests {
        let cmd = make_sysinfo_command(keyword);
        let output = send_to_hostd(&cmd).await?;
        let numeric = output.trim().trim_end_matches('%');
        let value = numeric.parse::<f32>().map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("failed to parse {} response: {}", keyword, output),
            )
        })?;
        values.push(value);
    }

    if values.len() != requests.len() {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "missing sysinfo responses"));
    }

    Ok(AgentInfo { cpu: values[0], mem: values[1], disk: values[2] })
}
