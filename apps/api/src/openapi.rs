use crate::{
    auth::AuthUser,
    commons::{
        error_logs::{Error_log, Level},
        CommonInfo, Date, Month, ResponseResult, ResponseType, Status, Time, UuidRequest, Week,
    },
    handles::login::LoginRequest,
};
use utoipa::OpenApi;

// TODO: 將所有有陸游的都需要添加到paths和schemas中

#[derive(OpenApi)]
#[openapi(
    paths(
        crate::handles::login::login,
        crate::handles::login::me,
        crate::handles::chm::backup::post_backup_root,
        crate::handles::chm::backup::get_backup_root,
        crate::handles::chm::backup::post_reduction,
    ),
    components(
        schemas(
            AuthUser,
            Level,
            Error_log,
            UuidRequest,
            ResponseType,
            ResponseResult,
            Month,
            Week,
            Time,
            Date,
            Status,
            CommonInfo,
            LoginRequest,
        )
    ),
    tags(
        (name = "Auth", description = "登入 / 身分驗證相關 API"),
        (name = "System", description = "系統錯誤 / Log 相關 API"),
        (name = "Backup", description = "CHM 備份相關 API"),
    )
)]
pub struct ApiDoc;
