use crate::commons::{ResponseResult as ApiResponseResult, ResponseType as ApiResponseType};
use actix_web::{http::StatusCode, HttpResponse, ResponseError};
use chm_grpc::{
    common::{ResponseResult as GrpcResponseResult, ResponseType as GrpcResponseType},
    tonic,
};
use thiserror::Error;
use tonic::{Code, Status};

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

#[derive(Debug, Error)]
#[error("{0}")]
pub struct GrpcError(#[from] Status);

impl ResponseError for GrpcError {
    fn status_code(&self) -> StatusCode {
        match self.0.code() {
            Code::Cancelled | Code::Unavailable => StatusCode::BAD_GATEWAY,
            Code::InvalidArgument | Code::FailedPrecondition => StatusCode::BAD_REQUEST,
            Code::NotFound => StatusCode::NOT_FOUND,
            Code::PermissionDenied | Code::Unauthenticated => StatusCode::UNAUTHORIZED,
            _ => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }
    fn error_response(&self) -> HttpResponse {
        HttpResponse::build(self.status_code()).body(self.0.message().to_string())
    }
}
