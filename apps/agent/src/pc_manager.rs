use crate::{execute_host_body, last_non_empty_line, ReturnInfo};

fn run_power_command(command: &str, success_message: &str) -> ReturnInfo {
    let script = format!("{command}\n");
    match execute_host_body(&script) {
        Ok(result) => {
            if result.status == 0 {
                ReturnInfo { type_field: "OK".to_string(), message: success_message.to_string() }
            } else {
                let output = result.output.trim();
                let message = if output.is_empty() {
                    format!("{success_message} 但系統回傳代碼 {}", result.status)
                } else if let Some(line) = last_non_empty_line(output) {
                    line.to_string()
                } else {
                    output.to_string()
                };
                ReturnInfo { type_field: "ERR".to_string(), message }
            }
        }
        Err(err) => ReturnInfo { type_field: "ERR".to_string(), message: err },
    }
}

pub fn execute_reboot() -> ReturnInfo {
    run_power_command("reboot", "reboot 指令已送出")
}

pub fn execute_shutdown() -> ReturnInfo {
    run_power_command("shutdown -h now", "shutdown 指令已送出")
}
