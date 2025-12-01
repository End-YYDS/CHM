use crate::{
    commons::{ResponseResult as ApiResponseResult, ResponseType as ApiResponseType},
    handles::chm::mca::types::{get_revokeds, get_valids, Revoked, Valid},
};
use chm_grpc::restful::{
    GetRevokedCertsResponse, GetValidCertsResponse, RevokeCertResponse, RevokedCert, ValidCert,
};
impl From<ValidCert> for Valid {
    fn from(v: ValidCert) -> Self {
        Self { name: v.name, signer: v.signer, period: v.period }
    }
}

impl From<GetValidCertsResponse> for get_valids {
    fn from(resp: GetValidCertsResponse) -> Self {
        Self {
            valid:  resp.valid.into_iter().map(Valid::from).collect::<Vec<Valid>>(),
            length: resp.length as usize,
        }
    }
}

impl From<RevokedCert> for Revoked {
    fn from(r: RevokedCert) -> Self {
        Self { number: r.number, time: r.time, reason: r.reason }
    }
}

impl From<GetRevokedCertsResponse> for get_revokeds {
    fn from(resp: GetRevokedCertsResponse) -> Self {
        Self {
            revoke: resp.revoke.into_iter().map(Revoked::from).collect::<Vec<Revoked>>(),
            length: resp.length as usize,
        }
    }
}

impl From<RevokeCertResponse> for ApiResponseResult {
    fn from(r: RevokeCertResponse) -> Self {
        match r.result {
            Some(inner) => inner.into(),
            None => ApiResponseResult {
                r#type:  ApiResponseType::Unspecified,
                message: "空的 RevokeCertResponse".to_string(),
            },
        }
    }
}
