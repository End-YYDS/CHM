mod types;

use actix_web::{get, put, web, HttpResponse, Scope};

use crate::commons::{ResponseResult, ResponseType};
use types::*;

// 以 thread-local 暫存設定值；實務可換成 DB 或全域 state。
thread_local! {
    static CURRENT_VALUES: std::cell::RefCell<Values> = std::cell::RefCell::new(Values::default());
}

pub fn values_scope() -> Scope {
    web::scope("/values").service(_get_values_root).service(_put_values_root)
}

/// GET /api/chm/setting/values
#[get("")]
async fn _get_values_root() -> HttpResponse {
    let v = CURRENT_VALUES.with(|cell| *cell.borrow());
    HttpResponse::Ok().json(v)
}

/// PUT /api/chm/setting/values
#[put("")]
async fn _put_values_root(data: web::Json<ValuesUpdate>) -> web::Json<ResponseResult> {
    CURRENT_VALUES.with(|cell| {
        let mut v = cell.borrow_mut();
        if let Some(x) = data.cpu_usage {
            v.cpu_usage = x;
        }
        if let Some(x) = data.disk_usage {
            v.disk_usage = x;
        }
        if let Some(x) = data.memory {
            v.memory = x;
        }
        if let Some(x) = data.network {
            v.network = x;
        }
    });

    web::Json(ResponseResult { r#type: ResponseType::Ok, message: "Values updated".into() })
}
