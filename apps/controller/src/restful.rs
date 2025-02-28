use actix_web::{get, HttpResponse};
#[get("/hello")]
async fn hello() -> HttpResponse {
    HttpResponse::Ok().body("Hello World")
}
pub fn rest_service() -> actix_web::Scope {
    actix_web::web::scope("/api").service(hello)
}
