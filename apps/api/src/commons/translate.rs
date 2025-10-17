use crate::commons::{ResponseResult as ApiResponseResult, ResponseType as ApiResponseType};
use chm_grpc::common::{ResponseResult as GrpcResponseResult, ResponseType as GrpcResponseType};

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
