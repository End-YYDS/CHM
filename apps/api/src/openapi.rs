use utoipa::OpenApi;

use crate::handles::{
    chm::{backup::BackupApi, mca::McaApi, pc_manager::PcManagerApi},
    login::AuthApi,
};

// TODO: 將所有有路由的都需要添加到paths和schemas中

#[derive(OpenApi)]
#[openapi(
    nest(
        (path = "/auth", api = AuthApi),
        (path = "/backup", api = BackupApi),
        (path = "/mca", api = McaApi),
        (path = "/pc", api = PcManagerApi),
    )
)]
pub struct ApiDoc;
