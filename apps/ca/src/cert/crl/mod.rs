mod simple;
mod verifier;

use std::sync::Arc;

use chrono::{DateTime, Utc};
use grpc::{
    crl::{crl_server::Crl, ListCrlEntriesRequest, ListCrlEntriesResponse},
    prost_types::Timestamp,
    tonic::{self, Request, Response, Status},
};
pub use simple::*;
pub use verifier::*;

use crate::cert::process::CertificateProcess;

pub struct CrlList {
    pub cert: Arc<CertificateProcess>,
}

#[tonic::async_trait]
impl Crl for CrlList {
    async fn list_crl_entries(
        &self,
        req: Request<ListCrlEntriesRequest>,
    ) -> Result<Response<ListCrlEntriesResponse>, Status> {
        let req = req.into_inner();
        let limit = req.limit as usize;
        let offset = req.offset as usize;
        let since_opt = req.since.and_then(|ts: Timestamp|
                // from_timestamp(ts.seconds, ts.nanos) 會回傳 Result<DateTime<Utc>, _>
                DateTime::<Utc>::from_timestamp(ts.seconds, ts.nanos as u32));
        dbg!(req);
        dbg!(limit);
        dbg!(offset);
        dbg!(since_opt);
        unimplemented!()
    }
}
