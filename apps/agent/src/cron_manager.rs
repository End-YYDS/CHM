// Functions: get_cron, cron_add, cron_delete, cron_update

use std::{
    collections::{HashMap, HashSet},
    io,
};

use crate::{
    execute_host_body, family_commands, make_sysinfo_command, send_to_hostd, shell_quote,
    ReturnInfo, SystemInfo,
};
use base64::{engine::general_purpose, Engine as _};
use serde::{Deserialize, Serialize};
use serde_json;
use uuid::Uuid;

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct CronSchedule {
    pub minute: i32,
    pub hour:   i32,
    pub date:   i32,
    pub month:  i32,
    pub week:   i32,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct CronJob {
    pub id:       String,
    pub name:     String,
    pub command:  String,
    pub schedule: CronSchedule,
    pub username: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct CronJobs {
    pub jobs:   Vec<CronJob>,
    pub length: usize,
}

const META_PREFIX: &str = "# agent_meta:";

#[derive(Debug, Serialize, Deserialize)]
struct CronMeta {
    id:   String,
    name: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct CronJobInput {
    pub name:     String,
    pub command:  String,
    pub schedule: CronSchedule,
    pub username: String,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct CronDeleteArg {
    #[serde(alias = "id", alias = "ID")]
    pub id: String,
}

pub async fn cron_info_structured(_sys: &SystemInfo) -> io::Result<CronJobs> {
    let cmd = make_sysinfo_command("cron_jobs");
    let output = send_to_hostd(&cmd).await?;

    if let Ok(jobs) = serde_json::from_str::<CronJobs>(&output) {
        return Ok(jobs);
    }

    if let Ok(info) = serde_json::from_str::<ReturnInfo>(&output) {
        return Err(io::Error::other(info.message));
    }

    Err(io::Error::new(
        io::ErrorKind::InvalidData,
        format!("failed to parse cron jobs JSON: {}", output.trim()),
    ))
}

pub async fn execute_cron_add(argument: &str, sys: &SystemInfo) -> Result<String, String> {
    let job_input: CronJobInput = serde_json::from_str(argument)
        .map_err(|e| format!("cron_add payload parse error: {}", e))?;

    validate_schedule(&job_input.schedule)?;

    let raw_id = Uuid::new_v4().simple().to_string();
    let id = format!("id{}", &raw_id[..8]);

    let job = CronJob {
        id:       id.clone(),
        name:     job_input.name,
        command:  job_input.command,
        schedule: job_input.schedule,
        username: job_input.username,
    };

    let mut lines = load_user_crontab(sys, &job.username).await?;
    if find_job_index(&lines, &job.id).is_some() {
        return Err(format!("cron job {} already exists", job.id));
    }

    let line = render_cron_line(&job)?;
    lines.push(line);
    save_user_crontab(sys, &job.username, &lines).await?;

    Ok(format!("cron_add: created job {} for {}", job.id, job.username))
}

pub async fn execute_cron_delete(argument: &str, sys: &SystemInfo) -> Result<String, String> {
    let id = parse_cron_delete_argument(Some(argument))?;
    let (username, mut lines, index) = locate_job_by_id(sys, &id).await?;
    lines.remove(index);
    save_user_crontab(sys, &username, &lines).await?;

    Ok(format!("cron_delete: removed job {}", id))
}

pub async fn execute_cron_update(argument: &str, sys: &SystemInfo) -> Result<String, String> {
    let jobs_map: HashMap<String, CronJobInput> = serde_json::from_str(argument)
        .map_err(|e| format!("cron_update payload parse error: {}", e))?;

    if jobs_map.is_empty() {
        return Err("cron_update requires at least one job".to_string());
    }

    let mut grouped: HashMap<String, Vec<CronJob>> = HashMap::new();
    for (id, job_input) in jobs_map {
        validate_schedule(&job_input.schedule)?;
        let job = CronJob {
            id,
            name: job_input.name,
            command: job_input.command,
            schedule: job_input.schedule,
            username: job_input.username,
        };
        grouped.entry(job.username.clone()).or_default().push(job);
    }

    let mut updated = 0usize;
    for (username, jobs) in grouped {
        let mut lines = load_user_crontab(sys, &username).await?;
        let mut changed = false;

        for job in jobs {
            if let Some(index) = find_job_index(&lines, &job.id) {
                lines[index] = render_cron_line(&job)?;
                changed = true;
                updated += 1;
            } else {
                return Err(format!("cron job {} not found for user {}", job.id, username));
            }
        }

        if changed {
            save_user_crontab(sys, &username, &lines).await?;
        }
    }

    Ok(format!("cron_update: updated {} job(s)", updated))
}

fn parse_cron_delete_argument(argument: Option<&str>) -> Result<String, String> {
    let raw = argument.ok_or_else(|| "cron_delete requires an id".to_string())?.trim();

    if raw.is_empty() {
        return Err("cron_delete requires an id".to_string());
    }

    if raw.starts_with('{') {
        let parsed: CronDeleteArg = serde_json::from_str(raw)
            .map_err(|e| format!("cron_delete payload parse error: {}", e))?;
        if parsed.id.trim().is_empty() {
            Err("cron_delete requires a non-empty id".to_string())
        } else {
            Ok(parsed.id)
        }
    } else {
        Ok(raw.to_string())
    }
}

async fn load_user_crontab(sys: &SystemInfo, username: &str) -> Result<Vec<String>, String> {
    let commands = family_commands(sys);
    let body = format!("{} -u {} -l\n", commands.crontab, shell_quote(username));
    let result = execute_host_body(&body).await?;

    match result.status {
        0 => Ok(result.output.lines().map(|l| l.to_string()).collect()),
        1 => Ok(Vec::new()),
        _ => {
            let message = if result.output.trim().is_empty() {
                format!("crontab -u {} -l failed with status {}", username, result.status)
            } else {
                result.output.trim().to_string()
            };
            Err(message)
        }
    }
}

async fn save_user_crontab(
    sys: &SystemInfo,
    username: &str,
    lines: &[String],
) -> Result<(), String> {
    let mut content = lines.join("\n");
    if !content.is_empty() {
        content.push('\n');
    }

    let encoded = general_purpose::STANDARD.encode(content.as_bytes());
    let commands = family_commands(sys);
    let body = format!(
        "TMP_FILE=$(mktemp)\ntrap 'rm -f \"$TMP_FILE\"' EXIT\nprintf '%s' {} | base64 -d \
         >\"$TMP_FILE\"\n{} -u {} \"$TMP_FILE\"\n",
        shell_quote(&encoded),
        commands.crontab,
        shell_quote(username)
    );

    let result = execute_host_body(&body).await?;
    if result.status == 0 {
        Ok(())
    } else {
        let message = if result.output.trim().is_empty() {
            format!("failed to install crontab for {} (status {})", username, result.status)
        } else {
            result.output.trim().to_string()
        };
        Err(message)
    }
}

fn find_job_index(lines: &[String], id: &str) -> Option<usize> {
    lines.iter().position(|line| {
        if let Some(meta) = extract_metadata(line) {
            meta.id == id
        } else {
            false
        }
    })
}

fn extract_metadata(line: &str) -> Option<CronMeta> {
    let idx = line.find(META_PREFIX)?;
    let meta_str = line[idx + META_PREFIX.len()..].trim();
    serde_json::from_str(meta_str).ok()
}

async fn locate_job_by_id(
    sys: &SystemInfo,
    id: &str,
) -> Result<(String, Vec<String>, usize), String> {
    for user in list_candidate_users(sys).await? {
        let lines = load_user_crontab(sys, &user).await?;
        if let Some(index) = find_job_index(&lines, id) {
            return Ok((user, lines, index));
        }
    }

    Err(format!("cron job {} not found", id))
}

async fn list_candidate_users(_sys: &SystemInfo) -> Result<Vec<String>, String> {
    let script =
        "found=0\nfor dir in /var/spool/cron /var/spool/cron/crontabs; do\n  if [ -d \"$dir\" ]; \
         then\n    for file in \"$dir\"/*; do\n      if [ -f \"$file\" ]; then\n        basename \
         \"$file\"\n        found=1\n      fi\n    done\n  fi\ndone\nif [ $found -eq 0 ]; then\n  \
         user_env=\"${USER-}\"\n  if [ -n \"$user_env\" ]; then\n    echo \"$user_env\"\n  fi\n  \
         username_env=\"${USERNAME-}\"\n  if [ -n \"$username_env\" ] && [ \"$username_env\" != \
         \"$user_env\" ]; then\n    echo \"$username_env\"\n  fi\nfi\n";

    let result = execute_host_body(script).await?;
    if result.status != 0 {
        let message = if result.output.trim().is_empty() {
            format!("failed to list cron users (status {})", result.status)
        } else {
            result.output.trim().to_string()
        };
        return Err(message);
    }

    let mut set = HashSet::new();
    for line in result.output.lines().map(str::trim).filter(|l| !l.is_empty()) {
        set.insert(line.to_string());
    }

    Ok(set.into_iter().collect())
}

fn render_cron_line(job: &CronJob) -> Result<String, String> {
    let minute = cron_value_to_field(job.schedule.minute, "Minute", 0, 59)?;
    let hour = cron_value_to_field(job.schedule.hour, "Hour", 0, 23)?;
    let date = cron_value_to_field(job.schedule.date, "Date", 1, 31)?;
    let month = cron_value_to_field(job.schedule.month, "Month", 1, 12)?;
    let week = cron_value_to_field(job.schedule.week, "Week", 0, 7)?;

    let meta = CronMeta { id: job.id.clone(), name: job.name.clone() };
    let meta_json = serde_json::to_string(&meta)
        .map_err(|e| format!("failed to encode cron metadata: {}", e))?;

    Ok(format!(
        "{minute} {hour} {date} {month} {week} {command} {meta_prefix}{meta_json}",
        minute = minute,
        hour = hour,
        date = date,
        month = month,
        week = week,
        command = job.command.trim(),
        meta_prefix = META_PREFIX,
        meta_json = meta_json,
    ))
}

fn cron_value_to_field(value: i32, field: &str, min: i32, max: i32) -> Result<String, String> {
    if value == -1 {
        return Ok("*".to_string());
    }

    if value < min || value > max {
        return Err(format!(
            "{} value {} out of range (expected {} to {} or -1)",
            field, value, min, max
        ));
    }

    Ok(value.to_string())
}

fn validate_schedule(schedule: &CronSchedule) -> Result<(), String> {
    cron_value_to_field(schedule.minute, "Minute", 0, 59)?;
    cron_value_to_field(schedule.hour, "Hour", 0, 23)?;
    cron_value_to_field(schedule.date, "Date", 1, 31)?;
    cron_value_to_field(schedule.month, "Month", 1, 12)?;
    cron_value_to_field(schedule.week, "Week", 0, 7)?;
    Ok(())
}
