#![allow(non_camel_case_types)]
#![allow(dead_code)]
use crate::commons::Date;
use serde::Serialize;

#[allow(clippy::upper_case_acronyms)]
#[derive(Debug, Serialize)]
pub enum QueryType {
    A,
    AAAA,
    CNAME,
    MX,
    NS,
    TXT,
    SRV,
    PTR,
    SOA,
    DNSKEY,
}

#[allow(clippy::upper_case_acronyms)]
#[derive(Debug, Serialize)]
pub enum Status {
    NOERROR,
    NXDOMAIN,
    SERVFAIL,
    REFUSED,
}

#[derive(Debug, Serialize)]
pub struct Query_log {
    #[serde(rename = "Client")]
    pub client:   String,
    #[serde(rename = "Date")]
    pub date:     Date,
    #[serde(rename = "Query")]
    pub query:    String,
    #[serde(rename = "Type")]
    pub r#type:   QueryType,
    #[serde(rename = "Response")]
    pub response: String,
    #[serde(rename = "Status")]
    pub status:   Status,
    #[serde(rename = "Duration")]
    pub duration: f64,
}
