use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::{
    auth::AuthUser,
    commons::{
        error_logs::{Error_log, Level},
        CommonInfo, Date, Month, ResponseResult, ResponseType, Status, Time, UuidRequest, Week,
    },
    handles::{
        chm::{
            backup::{
                BackupRequest, BackupResponse, GetBackupsRequest, GetBackupsResponse,
                ReductionRequest,
            },
            pc_manager::types::{
                DePatchVxlanid, DePutVxlanid, DeletePcGroupRequest, DeletePcRequest,
                DeletePcResponse, GetPcgroupResponseResult, PCManagerRequest, PatchPcgroupRequest,
                PcInformation, PostPcgroupRequest, PutPcgroupRequest, RebootPcResponse,
                ShutdownPcResponse, SpecificRequest, Uuid, UuidsRequest, Vxlanid,
            },
        },
        login::LoginRequest,
    },
};
/// 所有的 JSON Schema 集合
#[derive(Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "PascalCase")]
pub struct AllSchemas {
    pub auth:           AuthSchemas,
    pub common:         CommonSchemas,
    pub login:          LoginSchemas,
    pub chm_backup:     ChmBackupSchemas,
    pub chm_mca:        ChmMcaSchemas,
    pub chm_pc_manager: ChmPcManagerSchemas,
}

/// auth.rs相關的 JSON Schema
#[derive(Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "PascalCase")]
pub struct AuthSchemas {
    pub auth_user: AuthUser,
}

/// commons 相關的 JSON Schema
#[derive(Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "PascalCase")]
pub struct CommonSchemas {
    pub level:           Level,
    pub error_log:       Error_log,
    pub uuid_request:    UuidRequest,
    pub response_type:   ResponseType,
    pub response_result: ResponseResult,
    pub month:           Month,
    pub week:            Week,
    pub time:            Time,
    pub date:            Date,
    pub status:          Status,
    pub common_info:     CommonInfo,
}

/// handles/login 相關的 JSON Schema
#[derive(Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "PascalCase")]
pub struct LoginSchemas {
    pub login_request: LoginRequest,
}

/// handles/chm/backup 相關的 JSON Schema
#[derive(Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "PascalCase")]
pub struct ChmBackupSchemas {
    pub backup_request:       BackupRequest,
    pub backup_response:      BackupResponse,
    pub get_backups_request:  GetBackupsRequest,
    pub get_backups_response: GetBackupsResponse,
    pub reduction_request:    ReductionRequest,
}

/// handles/chm/mca 相關的 JSON Schema
#[derive(Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "PascalCase")]
pub struct ChmMcaSchemas {
    pub revoke_request: crate::handles::chm::mca::types::RevokeRequest,
    pub valid:          crate::handles::chm::mca::types::Valid,
    pub get_valids:     crate::handles::chm::mca::types::get_valids,
    pub revoked:        crate::handles::chm::mca::types::Revoked,
    pub get_revokeds:   crate::handles::chm::mca::types::get_revokeds,
}

/// handles/chm/pc_manager 相關的 JSON Schema
#[derive(Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "PascalCase")]
pub struct ChmPcManagerSchemas {
    pub pc_manager_request: PCManagerRequest,
    pub uuid: Uuid,
    pub pc_info: PcInformation,
    pub spectific_request: SpecificRequest,
    pub delete_pc_request: DeletePcRequest,
    pub delete_pc_response: DeletePcResponse,
    pub uuids_request: UuidsRequest,
    pub post_pc_group_request: PostPcgroupRequest,
    pub vxlan_id: Vxlanid,
    pub get_pc_group_response_result: GetPcgroupResponseResult,
    pub de_put_vxlan_id: DePutVxlanid,
    pub put_pc_group_request: PutPcgroupRequest,
    pub de_patch_vxlan_id: DePatchVxlanid,
    pub patch_pc_group_request: PatchPcgroupRequest,
    pub delete_pc_group_request: DeletePcGroupRequest,
    pub reboot_pc_response: RebootPcResponse,
    pub shutdown_pc_response: ShutdownPcResponse,
}
