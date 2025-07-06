mod verifier;
use crate::cert::store::CrlEntry as StoreCrlEntry;
use crate::{cert::process::CertificateProcess, globals::GlobalConfig, CaResult};
use chm_grpc::crl::CrlEntry as GrpcCrlEntry;
use chm_grpc::{
    crl::{crl_server::Crl, ListCrlEntriesRequest, ListCrlEntriesResponse},
    prost::Message,
    prost_types::Timestamp,
    tonic::{self, Request, Response, Status},
};
use chrono::{DateTime, Duration, TimeZone, Utc};
use std::sync::Arc;
pub use verifier::*;

impl From<StoreCrlEntry> for GrpcCrlEntry {
    fn from(se: StoreCrlEntry) -> Self {
        GrpcCrlEntry {
            serial: se.cert_serial.unwrap_or_default(),
            revoked_at: Some(Timestamp {
                seconds: se.revoked_at.timestamp(),
                nanos: se.revoked_at.timestamp_subsec_nanos() as i32,
            }),
            reason: se.reason.unwrap_or_default(),
        }
    }
}

pub struct CrlList {
    pub cert: Arc<CertificateProcess>,
}
impl CrlList {
    pub async fn next_update_time(&self) -> CaResult<DateTime<Utc>> {
        let interval_std = GlobalConfig::read()
            .await
            .settings
            .certificate
            .crl_update_interval;
        let interval =
            Duration::from_std(interval_std).map_err(|e| format!("Invalid interval: {e}"))?;
        Ok(Utc::now() + interval)
    }
    /// CRL number = (now - 基準日) 的分鐘數
    pub fn current_crl_number(&self) -> CaResult<u64> {
        let base: DateTime<Utc> = Utc.with_ymd_and_hms(2025, 1, 1, 0, 0, 0).single().unwrap();
        let mins = (Utc::now() - base).num_minutes();
        Ok(if mins > 0 { mins as u64 } else { 0 })
    }
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
        let since = req
            .since
            .and_then(|ts: Timestamp| DateTime::<Utc>::from_timestamp(ts.seconds, ts.nanos as u32));
        let store_entries = self
            .cert
            .get_store()
            .list_crl_entries(since, limit, offset)
            .await
            .map_err(|e| Status::internal(format!("CRL 查詢失敗: {e}")))?;
        let grpc_entries: Vec<GrpcCrlEntry> = store_entries.into_iter().map(Into::into).collect();
        let now = Utc::now();
        let this_update = Some(Timestamp {
            seconds: now.timestamp(),
            nanos: now.timestamp_subsec_nanos() as i32,
        });
        let next = self
            .next_update_time()
            .await
            .map_err(|e| Status::internal(format!("計算 next_update 失敗: {e}")))?;
        let next_update = Timestamp {
            seconds: next.timestamp(),
            nanos: next.timestamp_subsec_nanos() as i32,
        };
        let crl_number = self
            .current_crl_number()
            .map_err(|e| Status::internal(format!("計算 crl_number 失敗: {e}")))?;
        let mut resp = ListCrlEntriesResponse {
            entries: grpc_entries,
            this_update,
            next_update: Some(next_update),
            crl_number,
            signature: vec![],
        };
        let raw = Message::encode_to_vec(&resp);
        resp.signature = self
            .cert
            .sign_crl(&raw)
            .map_err(|e| Status::internal(format!("CRL 簽名失敗: {e}")))?;
        Ok(Response::new(resp)) //TODO: 驗證CRL簽名
    }
}
