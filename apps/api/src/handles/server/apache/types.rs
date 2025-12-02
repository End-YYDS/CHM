use crate::{commons::CommonInfo, handles::server::apache::logs::Logs};
use serde::Serialize;
use utoipa::ToSchema;

#[derive(Debug, Serialize, ToSchema)]
#[serde(deny_unknown_fields, rename_all = "PascalCase")]
pub struct ApacheResponse {
    #[serde(flatten)]
    pub common_info: CommonInfo,
    pub connections: i64,
    pub logs:        Logs,
}
