use actix_session::Session;
use actix_web::{
    dev::Payload, error::ErrorUnauthorized, Error, FromRequest, HttpMessage, HttpRequest,
};
use serde::{Deserialize, Serialize};
use std::future::{ready, Ready};
use utoipa::ToSchema;

#[derive(Debug, Clone, Copy)]
pub struct RequireLogin;

/// 認證使用者資訊
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields, rename_all = "PascalCase")]
pub struct AuthUser {
    pub uid:      String,
    pub username: Option<String>,
    pub role:     Option<String>,
}

impl FromRequest for RequireLogin {
    type Error = Error;
    type Future = Ready<Result<Self, Self::Error>>;

    fn from_request(req: &HttpRequest, _: &mut Payload) -> Self::Future {
        if req.extensions().get::<AuthUser>().is_some() {
            return ready(Ok(RequireLogin));
        }
        let session = match Session::extract(req).into_inner() {
            Ok(s) => s,
            Err(_) => return ready(Err(ErrorUnauthorized("no session"))),
        };
        match session.get::<String>("uid") {
            Ok(Some(_)) => ready(Ok(RequireLogin)),
            _ => ready(Err(ErrorUnauthorized("unauthorized"))),
        }
    }
}

impl FromRequest for AuthUser {
    type Error = Error;
    type Future = Ready<Result<Self, Self::Error>>;

    fn from_request(req: &HttpRequest, _: &mut Payload) -> Self::Future {
        if let Some(user) = req.extensions().get::<AuthUser>() {
            return ready(Ok(user.clone()));
        }
        let session = match Session::extract(req).into_inner() {
            Ok(s) => s,
            Err(_) => return ready(Err(ErrorUnauthorized("no session"))),
        };
        let uid = match session.get::<String>("uid") {
            Ok(Some(v)) => v,
            _ => return ready(Err(ErrorUnauthorized("unauthorized"))),
        };
        let username = session.get::<String>("username").ok().flatten();
        let role = session.get::<String>("role").ok().flatten();
        let user = AuthUser { uid, username, role };
        req.extensions_mut().insert(user.clone());
        ready(Ok(user))
    }
}
