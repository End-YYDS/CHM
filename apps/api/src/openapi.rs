// TODO: 將所有有路由的都需要添加到paths和schemas中
use utoipa::{
    openapi::{OpenApi, Server},
    OpenApi as _,
};

use crate::handles::{
    chm::{backup::BackupApiDoc, mca::McaApiDoc, pc_manager::PcManagerApiDoc}, info::InfoApiDoc, login::LoginApiDocs, logout::LogoutApiDocs
};
pub fn build_openapi() -> OpenApi {
    let mut doc = LoginApiDocs::openapi();
    doc.merge(LogoutApiDocs::openapi());
    doc.merge(BackupApiDoc::openapi());
    doc.merge(McaApiDoc::openapi());
    doc.merge(PcManagerApiDoc::openapi());
    doc.merge(InfoApiDoc::openapi());

    doc.servers = Some(vec![Server::new("/api")]);
    doc
}
