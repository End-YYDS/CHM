// TODO: 將所有有路由的都需要添加到paths和schemas中
use utoipa::{
    openapi::{OpenApi, Server},
    OpenApi as _,
};

use crate::handles::{
    chm::{
        backup::BackupApiDoc, group::ChmGroupApiDoc, mca::McaApiDoc, pc_manager::PcManagerApiDoc,
        user::ChmUserApiDoc,
    },
    info::InfoApiDoc,
    login::LoginApiDocs,
    logout::LogoutApiDocs,
    server::{apache::ServerApacheApiDoc, ServerApiDoc},
    software::SoftWareApiDoc,
};
pub fn build_openapi() -> OpenApi {
    let mut doc = LoginApiDocs::openapi();
    doc.merge(LogoutApiDocs::openapi());
    doc.merge(BackupApiDoc::openapi());
    doc.merge(McaApiDoc::openapi());
    doc.merge(PcManagerApiDoc::openapi());
    doc.merge(InfoApiDoc::openapi());
    doc.merge(ServerApacheApiDoc::openapi());
    doc.merge(ChmUserApiDoc::openapi());
    doc.merge(ChmGroupApiDoc::openapi());
    doc.merge(ServerApiDoc::openapi());
    doc.merge(SoftWareApiDoc::openapi());

    doc.servers = Some(vec![Server::new("/api")]);
    doc
}
