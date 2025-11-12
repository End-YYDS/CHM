use std::io;

use crate::commons::{ResponseResult as ApiResponseResult, ResponseType as ApiResponseType};
use actix_web::{http::StatusCode, HttpResponse, ResponseError};
use chm_grpc::{
    common::{ResponseResult as GrpcResponseResult, ResponseType as GrpcResponseType},
    tonic,
};
use thiserror::Error;
use tonic::{Code, Status};
use url::ParseError as UrlParseError;

impl From<GrpcResponseType> for ApiResponseType {
    fn from(r: GrpcResponseType) -> Self {
        match r {
            GrpcResponseType::Ok => ApiResponseType::Ok,
            GrpcResponseType::Err => ApiResponseType::Err,
            GrpcResponseType::Unspecified => ApiResponseType::Unspecified,
        }
    }
}

impl From<GrpcResponseResult> for ApiResponseResult {
    fn from(r: GrpcResponseResult) -> Self {
        Self { r#type: ApiResponseType::from(r.r#type()), message: r.message }
    }
}

// #[derive(Debug, Error)]
// #[error("{0}")]
// pub struct GrpcError(#[from] Status);

// impl ResponseError for GrpcError {
//     fn status_code(&self) -> StatusCode {
//         match self.0.code() {
//             Code::Cancelled | Code::Unavailable => StatusCode::BAD_GATEWAY,
//             Code::InvalidArgument | Code::FailedPrecondition => StatusCode::BAD_REQUEST,
//             Code::NotFound => StatusCode::NOT_FOUND,
//             Code::PermissionDenied | Code::Unauthenticated => StatusCode::UNAUTHORIZED,
//             _ => StatusCode::INTERNAL_SERVER_ERROR,
//         }
//     }
//     fn error_response(&self) -> HttpResponse {
//         HttpResponse::build(self.status_code()).body(self.0.message().to_string())
//     }
// }

#[derive(Debug, Error)]
pub enum AppError {
    #[error("gRPC error: {0}")]
    Grpc(#[from] Status),

    #[error("Invalid URL: {0}")]
    InvalidUrl(#[from] UrlParseError),

    #[error("Invalid IP address: {0}")]
    InvalidIpAddress(String),

    #[error("I/O error: {0}")]
    Io(#[from] io::Error),

    #[error("Unknown error: {0}")]
    Other(String),
}
impl ResponseError for AppError {
    fn status_code(&self) -> StatusCode {
        match self {
            AppError::Grpc(status) => match status.code() {
                Code::Cancelled | tonic::Code::Unavailable => StatusCode::BAD_GATEWAY,
                Code::InvalidArgument | tonic::Code::FailedPrecondition => StatusCode::BAD_REQUEST,
                Code::NotFound => StatusCode::NOT_FOUND,
                Code::PermissionDenied | tonic::Code::Unauthenticated => StatusCode::UNAUTHORIZED,
                _ => StatusCode::INTERNAL_SERVER_ERROR,
            },
            AppError::InvalidUrl(_) => StatusCode::BAD_REQUEST,
            AppError::InvalidIpAddress(_) => StatusCode::BAD_REQUEST,
            AppError::Io(_) => StatusCode::INTERNAL_SERVER_ERROR,
            AppError::Other(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    fn error_response(&self) -> HttpResponse {
        HttpResponse::build(self.status_code()).body(self.to_string())
    }
}
