use actix_web::{get, post, web};
use chm_grpc::{common, restful};
use std::convert::TryFrom;
use utoipa::OpenApi;

use crate::{
    commons::{
        error_logs::{Error_log, Level},
        translate::AppError,
        Date, Month, ResponseResult, ResponseType, Time, UuidRequest, Week,
    },
    handles::server::{
        apache::{logs::Logs, types::ApacheResponse},
        convert_action_result, convert_common_info,
    },
    AppState, RestfulResult,
};

mod logs;
mod types;

#[derive(OpenApi)]
#[openapi(
    paths(get_apache_all, action_start, action_stop,action_restart),
    tags(
        (name = "Apache", description = "Apache 相關 API")
    )
)]
pub struct ServerApacheApiDoc;

#[utoipa::path(
    get,
    path = "/server/apache",
    params(
        UuidRequest
    ),
    tag = "Apache",
    responses(
        (status = 200, body = ApacheResponse),
    )
)]
#[get("")]
async fn get_apache_all(
    app_state: web::Data<AppState>,
    query: web::Query<UuidRequest>,
) -> RestfulResult<web::Json<ApacheResponse>> {
    let uuid = extract_uuid(&query.uuid)?;
    let mut client = app_state.gclient.clone();
    let resp = client.get_apache_status(restful::GetApacheRequest { uuid }).await?.into_inner();
    let converted = convert_apache_response(resp)?;
    Ok(web::Json(converted))
}

pub fn apache_scope() -> actix_web::Scope {
    web::scope("/apache").service(get_apache_all).service(action_scope())
}

fn action_scope() -> actix_web::Scope {
    web::scope("/action").service(action_start).service(action_stop).service(action_restart)
}

#[utoipa::path(
    post,
    path = "/server/apache/action/start",
    tag = "Apache",
    request_body = UuidRequest,
    responses(
        (status = 200, body = ResponseResult),
    )
)]
#[post("/start")]
async fn action_start(
    app_state: web::Data<AppState>,
    web::Json(payload): web::Json<UuidRequest>,
) -> RestfulResult<web::Json<ResponseResult>> {
    let uuid = extract_uuid(&payload.uuid)?;
    let mut client = app_state.gclient.clone();
    let req = restful::StartApacheRequest { inner: Some(restful::ApacheActionRequest { uuid }) };
    let resp = client.start_apache(req).await?.into_inner();
    let result = resp
        .result
        .map(convert_action_result)
        .unwrap_or(ResponseResult { r#type: ResponseType::Ok, message: String::new() });
    Ok(web::Json(result))
}

#[utoipa::path(
    post,
    path = "/server/apache/action/stop",
    tag = "Apache",
    request_body = UuidRequest,
    responses(
        (status = 200, body = ResponseResult),
    )
)]
#[post("/stop")]
async fn action_stop(
    app_state: web::Data<AppState>,
    web::Json(payload): web::Json<UuidRequest>,
) -> RestfulResult<web::Json<ResponseResult>> {
    let uuid = extract_uuid(&payload.uuid)?;
    let mut client = app_state.gclient.clone();
    let req = restful::StopApacheRequest { inner: Some(restful::ApacheActionRequest { uuid }) };
    let resp = client.stop_apache(req).await?.into_inner();
    let result = resp
        .result
        .map(convert_action_result)
        .unwrap_or(ResponseResult { r#type: ResponseType::Ok, message: String::new() });
    Ok(web::Json(result))
}

#[utoipa::path(
    post,
    path = "/server/apache/action/restart",
    tag = "Apache",
    request_body = UuidRequest,
    responses(
        (status = 200, body = ResponseResult),
    )
)]
#[post("/restart")]
async fn action_restart(
    app_state: web::Data<AppState>,
    web::Json(payload): web::Json<UuidRequest>,
) -> RestfulResult<web::Json<ResponseResult>> {
    let uuid = extract_uuid(&payload.uuid)?;
    let mut client = app_state.gclient.clone();
    let req = restful::RestartApacheRequest { inner: Some(restful::ApacheActionRequest { uuid }) };
    let resp = client.restart_apache(req).await?.into_inner();
    let result = resp
        .result
        .map(convert_action_result)
        .unwrap_or(ResponseResult { r#type: ResponseType::Ok, message: String::new() });
    Ok(web::Json(result))
}

#[allow(clippy::result_large_err)]
fn extract_uuid(raw: &str) -> RestfulResult<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(AppError::BadRequest("Uuid 不可為空".into()));
    }
    Ok(trimmed.to_string())
}

#[allow(clippy::result_large_err)]
fn convert_apache_response(resp: restful::GetApacheResponse) -> RestfulResult<ApacheResponse> {
    let common_info = resp
        .common_info
        .map(convert_common_info)
        .ok_or_else(|| AppError::Other("Controller 未回傳 Apache 資訊".into()))?;
    let logs = resp.logs.map(convert_logs).unwrap_or_else(default_logs);
    Ok(ApacheResponse { common_info, connections: resp.connections, logs })
}

fn convert_logs(logs: restful::ApacheLogs) -> Logs {
    let error_log = logs.error_log.into_iter().filter_map(convert_error_log).collect();
    let access_log = logs.access_log.into_iter().filter_map(convert_access_log).collect();
    Logs {
        error_log,
        errlength: logs.errlength as usize,
        access_log,
        acclength: logs.acclength as usize,
    }
}

fn convert_error_log(log: common::ErrorLog) -> Option<Error_log> {
    let date = log.date.and_then(convert_date)?;
    let level = convert_log_level(common::LogLevel::try_from(log.level).ok());
    Some(Error_log {
        date,
        module: log.module,
        level,
        pid: i64::try_from(log.pid).unwrap_or(0),
        client: log.client,
        message: log.message,
    })
}

fn convert_access_log(
    log: restful::ApacheAccessLog,
) -> Option<crate::handles::server::apache::logs::access_log::Access_log> {
    let date = log.date.and_then(convert_date)?;
    Some(crate::handles::server::apache::logs::access_log::Access_log {
        ip: log.ip,
        date,
        method: log.method,
        url: log.url,
        protocol: log.protocol,
        status: log.status,
        byte: log.byte,
        referer: log.referer,
        user_agent: log.user_agent,
    })
}

fn convert_date(date: common::Date) -> Option<Date> {
    let month_enum = common::Month::try_from(date.month).unwrap_or(common::Month::Unspecified);
    let week_enum = common::Week::try_from(date.week).unwrap_or(common::Week::Unspecified);
    let time = date
        .time
        .map(|t| Time {
            hour: i64::try_from(t.hour).unwrap_or(0),
            min:  i64::try_from(t.min).unwrap_or(0),
        })
        .unwrap_or(Time { hour: 0, min: 0 });
    Some(Date {
        year: i64::try_from(date.year).unwrap_or(0),
        month: convert_month(month_enum),
        day: i64::try_from(date.day).unwrap_or(0),
        week: convert_week(week_enum),
        time,
    })
}

fn convert_month(value: common::Month) -> Month {
    match value {
        common::Month::Jan => Month::Jan,
        common::Month::Feb => Month::Feb,
        common::Month::Mar => Month::Mar,
        common::Month::Apr => Month::Apr,
        common::Month::May => Month::May,
        common::Month::Jun => Month::Jun,
        common::Month::Jul => Month::Jul,
        common::Month::Aug => Month::Aug,
        common::Month::Sep => Month::Sep,
        common::Month::Oct => Month::Oct,
        common::Month::Nov => Month::Nov,
        common::Month::Dec => Month::Dec,
        common::Month::Unspecified => Month::Jan,
    }
}

fn convert_week(value: common::Week) -> Week {
    match value {
        common::Week::Mon => Week::Mon,
        common::Week::Tue => Week::Tue,
        common::Week::Wed => Week::Wed,
        common::Week::Thu => Week::Thu,
        common::Week::Fri => Week::Fri,
        common::Week::Sat => Week::Sat,
        common::Week::Sun => Week::Sun,
        common::Week::Unspecified => Week::Mon,
    }
}

fn convert_log_level(value: Option<common::LogLevel>) -> Level {
    match value.unwrap_or(common::LogLevel::Info) {
        common::LogLevel::Debug => Level::debug,
        common::LogLevel::Info => Level::info,
        common::LogLevel::Notice => Level::notice,
        common::LogLevel::Warn => Level::warn,
        common::LogLevel::Error => Level::error,
        common::LogLevel::Crit => Level::crit,
        common::LogLevel::Alert => Level::alert,
        common::LogLevel::Emerg => Level::emerg,
        common::LogLevel::Unspecified => Level::info,
    }
}

fn default_logs() -> Logs {
    Logs { error_log: Vec::new(), errlength: 0, access_log: Vec::new(), acclength: 0 }
}
