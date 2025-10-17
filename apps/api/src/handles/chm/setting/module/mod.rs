mod types;

use crate::{
    commons::ResponseResult,
    handles::chm::setting::module::types::{
        DeleteModuleReport, DeleteModuleRequest, DeleteModuleResponse, EnableStatus, LoadStatus,
        ModuleCollection, ModuleReport, ModuleResponse, ModuleUploadForm, PutModuleReport,
        PutModuleResponse,
    },
};
use actix_multipart::form::MultipartForm;
use actix_web::{delete, get, patch, post, put, web, Scope};

pub fn module_scope() -> Scope {
    web::scope("/module")
        .service(_get_module_root)
        .service(_post_module_root)
        .service(_put_module_root)
        .service(_patch_module_root)
        .service(_delete_module_root)
        .service(_post_module_action_enable)
        .service(_post_module_action_disable)
}

#[get("")]
async fn _get_module_root() -> web::Json<ModuleCollection> {
    let mut modules = std::collections::HashMap::new();

    modules.insert(
        "ExampleModule".to_string(),
        types::Module {
            name:          "ExampleModule".to_string(),
            version:       "1.0.0".to_string(),
            description:   "This is an example module.".to_string(),
            author:        "".to_string(),
            load_status:   LoadStatus::Load,
            enable_status: EnableStatus::Disable,
        },
    );
    let length = modules.len();
    web::Json(ModuleCollection { modules, length })
}
#[post("")]
async fn _post_module_root(
    MultipartForm(form): MultipartForm<ModuleUploadForm>,
) -> web::Json<ModuleResponse> {
    dbg!(&form);
    let load = vec!["ExampleModule".to_string()];
    let notload = vec!["Test".to_string()];
    let load_length = load.len();
    let notload_length = notload.len();
    web::Json(ModuleResponse {
        module: ModuleReport { load, notload, load_length, notload_length },
    })
}

#[put("")]
async fn _put_module_root(
    MultipartForm(form): MultipartForm<ModuleUploadForm>,
) -> web::Json<PutModuleResponse> {
    dbg!(&form);
    let success = vec!["ExampleModule".to_string()];
    let fail = vec!["Test".to_string()];
    let success_length = success.len();
    let fail_length = fail.len();
    web::Json(PutModuleResponse {
        module: PutModuleReport { success, fail, success_length, fail_length },
    })
}

#[patch("")]
async fn _patch_module_root(
    MultipartForm(form): MultipartForm<ModuleUploadForm>,
) -> web::Json<ResponseResult> {
    dbg!(&form);
    web::Json(ResponseResult {
        r#type:  crate::commons::ResponseType::Ok,
        message: "Module patched successfully".to_string(),
    })
}

#[delete("")]
async fn _delete_module_root(
    data: web::Json<DeleteModuleRequest>,
) -> web::Json<DeleteModuleResponse> {
    dbg!(&data);
    let delete = vec!["ExampleModule".to_string()];
    let not_delete = vec!["NonExistentModule".to_string()];
    let delete_length = delete.len();
    let not_delete_length = not_delete.len();
    web::Json(DeleteModuleResponse {
        module: DeleteModuleReport { delete, not_delete, delete_length, not_delete_length },
    })
}
#[post("/action/enable")]
async fn _post_module_action_enable(
    data: web::Json<DeleteModuleRequest>,
) -> web::Json<PutModuleResponse> {
    dbg!(&data);
    let success = data.modules.clone();
    let fail = vec![];
    web::Json(PutModuleResponse {
        module: PutModuleReport {
            success_length: success.len(),
            fail_length: fail.len(),
            success,
            fail,
        },
    })
}

#[post("/action/disable")]
async fn _post_module_action_disable(
    data: web::Json<DeleteModuleRequest>,
) -> web::Json<PutModuleResponse> {
    dbg!(&data);
    let success = data.modules.clone();
    let fail = vec![];
    web::Json(PutModuleResponse {
        module: PutModuleReport {
            success_length: success.len(),
            fail_length: fail.len(),
            success,
            fail,
        },
    })
}
