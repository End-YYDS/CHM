use chm_grpc::{
    crl::{crl_client::CrlClient, ListCrlEntriesRequest},
    prost::Message,
    prost_types::Timestamp,
    tonic::{self, async_trait, transport::Channel},
};
use chrono::{DateTime, Utc};
use openssl::{hash::MessageDigest, pkey::PKey, sign::Verifier, x509::X509};
use thiserror::Error;

use crate::{CrlCacheError, CrlProvider};
#[derive(Debug, Error)]
pub enum GrpcProviderError {
    #[error("transport error: {0}")]
    Transport(#[from] tonic::transport::Error),

    #[error("openssl error: {0}")]
    Tls(#[from] openssl::error::ErrorStack),

    #[error("grpc status error: {0}")]
    Status(#[from] tonic::Status),

    #[error("missing `{0}` in response")]
    MissingField(&'static str),

    #[error("signature verification failed")]
    BadSignature,
}
#[derive(Debug)]
pub struct GrpcCrlProvider {
    client:    CrlClient<Channel>,
    ca_pubkey: PKey<openssl::pkey::Public>,
}

impl GrpcCrlProvider {
    pub async fn new(
        endpoint: impl Into<String>,
        ca_cert_pem: &[u8],
    ) -> Result<Self, GrpcProviderError> {
        let client = CrlClient::connect(endpoint.into()).await?;
        let cert = X509::from_pem(ca_cert_pem)?;
        let ca_pubkey = cert.public_key()?;
        Ok(Self { client, ca_pubkey })
    }
    fn ts_to_datetime(ts: Timestamp) -> DateTime<Utc> {
        DateTime::<Utc>::from_timestamp(ts.seconds, ts.nanos as u32).unwrap()
    }
}

#[async_trait]
impl CrlProvider for GrpcCrlProvider {
    async fn fetch_crl(
        &self,
        since: Option<DateTime<Utc>>,
        limit: usize,
        offset: usize,
    ) -> Result<(Vec<String>, DateTime<Utc>, DateTime<Utc>), CrlCacheError> {
        let req = ListCrlEntriesRequest {
            since:  since.map(|dt| Timestamp {
                seconds: dt.timestamp(),
                nanos:   dt.timestamp_subsec_nanos() as i32,
            }),
            limit:  limit as u32,
            offset: offset as u32,
        };
        let resp = self
            .client
            .clone()
            .list_crl_entries(req)
            .await
            .map_err(|e| CrlCacheError::ProviderError(e.to_string()))?
            .into_inner();
        let mut unsigned = resp.clone();
        unsigned.signature = Vec::new();
        let raw = Message::encode_to_vec(&unsigned);

        let mut verifier = Verifier::new(MessageDigest::sha256(), &self.ca_pubkey)
            .map_err(|e| CrlCacheError::ProviderError(format!("Verifier init failed: {e}")))?;
        verifier
            .update(&raw)
            .map_err(|e| CrlCacheError::ProviderError(format!("Verifier update failed: {e}")))?;
        if !verifier
            .verify(&resp.signature)
            .map_err(|e| CrlCacheError::ProviderError(format!("Signature check error: {e}")))?
        {
            return Err(CrlCacheError::ProviderError("Invalid CRL signature".into()));
        }
        let entries = resp.entries.into_iter().map(|e| e.serial).collect::<Vec<_>>();

        let this_ts = resp
            .this_update
            .ok_or_else(|| CrlCacheError::ProviderError("missing this_update".into()))?;
        let next_ts = resp
            .next_update
            .ok_or_else(|| CrlCacheError::ProviderError("missing next_update".into()))?;

        let this_update = GrpcCrlProvider::ts_to_datetime(this_ts);
        let next_update = GrpcCrlProvider::ts_to_datetime(next_ts);

        Ok((entries, this_update, next_update))
    }
}
