use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

/// 憑證吊銷請求
#[derive(Debug, Serialize, Deserialize, JsonSchema, ToSchema)]
#[serde(deny_unknown_fields, rename_all = "PascalCase")]
pub struct RevokeRequest {
    pub name:   String,
    pub reason: String,
}

/// 憑證有效清單(個體)
#[derive(Debug, Serialize, Deserialize, JsonSchema, ToSchema)]
#[serde(deny_unknown_fields, rename_all = "PascalCase")]
pub struct Valid {
    pub name:   String,
    pub signer: String,
    pub period: String,
}

/// 憑證有效清單
#[derive(Debug, Serialize, Deserialize, JsonSchema, ToSchema)]
#[serde(deny_unknown_fields, rename_all = "PascalCase")]
pub struct get_valids {
    pub valid:  Vec<Valid>,
    pub length: usize,
}

/// 憑證吊銷清單(個體)
#[derive(Debug, Serialize, Deserialize, JsonSchema, ToSchema)]
#[serde(deny_unknown_fields, rename_all = "PascalCase")]
pub struct Revoked {
    pub number: String,
    pub time:   String,
    pub reason: String,
}

/// 憑證吊銷清單
#[derive(Debug, Serialize, Deserialize, JsonSchema, ToSchema)]
#[serde(deny_unknown_fields, rename_all = "PascalCase")]
pub struct get_revokeds {
    pub revoke: Vec<Revoked>,
    pub length: usize,
}
