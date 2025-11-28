// use utoipa::OpenApi;

// use crate::handles::{
//     chm::{backup::BackupApi, mca::McaApi, pc_manager::PcManagerApi},
//     login::AuthApi,
// };

// TODO: 將所有有路由的都需要添加到paths和schemas中

// #[derive(OpenApi)]
// #[openapi(
//     servers(
//         (url = "/api")
//     ),
//     nest(
//         (path = "/auth", api = AuthApi),
//         (path = "/backup", api = BackupApi),
//         (path = "/mca", api = McaApi),
//         (path = "/pc", api = PcManagerApi),
//     )
// )]
// pub struct ApiDoc;
use utoipa::{
    openapi::{OpenApi, Server},
    OpenApi as _,
};

use crate::handles::{
    chm::{backup::BackupApiDoc, mca::McaApiDoc, pc_manager::PcManagerApiDoc},
    login::LoginApiDocs,
    logout::LogoutApiDocs,
};
pub fn build_openapi() -> OpenApi {
    let mut doc = LoginApiDocs::openapi();
    doc.merge(LogoutApiDocs::openapi());
    doc.merge(BackupApiDoc::openapi());
    doc.merge(McaApiDoc::openapi());
    doc.merge(PcManagerApiDoc::openapi());

    doc.servers = Some(vec![Server::new("/api")]);

    doc
}
