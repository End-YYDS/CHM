use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Serialize, Deserialize, Clone, Copy)]
pub struct Schedule {
    #[serde(rename = "Minute")]
    pub minute: i64,
    #[serde(rename = "Hour")]
    pub hour:   i64,
    #[serde(rename = "Date")]
    pub date:   i64,
    #[serde(rename = "Month")]
    pub month:  i64,
    #[serde(rename = "Week")]
    pub week:   i64,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct CronJobEntry {
    #[serde(rename = "Name")]
    pub name:     String,
    #[serde(rename = "Command")]
    pub command:  String,
    #[serde(rename = "Schedule")]
    pub schedule: Schedule,
    #[serde(rename = "Username")]
    pub username: String,
}

#[derive(Debug, Serialize)]
pub struct GetAllResponse {
    #[serde(rename = "Jobs")]
    pub jobs:   HashMap<String, CronJobEntry>,
    #[serde(rename = "length")]
    pub length: usize,
}

// POST /api/cron
pub type CreateCronRequest = CronJobEntry;

// DELETE /api/cron
#[derive(Debug, Deserialize)]
pub struct DeleteCronRequest {
    #[serde(rename = "id")]
    pub id: String,
}

// PUT /api/cron  — 以 id 做 key 的整筆更新
#[derive(Debug, Deserialize)]
pub struct PutCronRequest {
    #[serde(flatten)]
    pub items: HashMap<String, CronJobEntry>,
}
