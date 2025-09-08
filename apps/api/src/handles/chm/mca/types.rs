use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize)]
pub struct RevokeRequest {
    #[serde(rename = "Name")]
    pub name:   String,
    #[serde(rename = "Reason")]
    pub reason: String,
}

#[derive(Debug, Serialize)]
pub struct Valid {
    #[serde(rename = "Name")]
    pub name:   String,
    #[serde(rename = "Signer")]
    pub signer: String,
    #[serde(rename = "Period")]
    pub period: String,
}

#[derive(Debug, Serialize)]
pub struct get_valid {
    #[serde(rename = "Valid")]
    pub valid:  Valid,
    #[serde(rename = "Length")]
    pub length: usize,
}

#[derive(Debug, Serialize)]
pub struct Revoked {
    #[serde(rename = "Number")]
    pub number: String,
    #[serde(rename = "Time")]
    pub time:   String,
    #[serde(rename = "Reason")]
    pub reason: String,
}

#[derive(Debug, Serialize)]
pub struct get_revoked {
    #[serde(rename = "Revoke")]
    pub revoke: Revoked,
    #[serde(rename = "Length")]
    pub length: usize,
}

// {
// {
// "Revoke": {
// "Number": String, //序號
// "Time": String, //吊銷當下的時間
// "Reason": String,
// },
// "Length": Revoke.len,
// },
