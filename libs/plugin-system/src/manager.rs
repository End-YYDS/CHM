use std::path::{Path, PathBuf};

use crate::types::{PluginCreate, PluginEntry, Plugins, Routes};
// use actix_web::{web, HttpRequest};
use actix_web::web;
use plugin_lib::{types::PluginMeta, Plugin};
use std::sync::atomic::{AtomicUsize, Ordering};

#[derive(Default, Debug)]
pub struct PluginManager {
    plugins: Plugins,
    routes: Routes,
    plugin_dir: PathBuf,
    next_id: AtomicUsize,
}

impl PluginManager {
    pub fn new<P: AsRef<Path>>(plugin_dir: P) -> Self {
        Self {
            plugins: Plugins::default(),
            routes: Routes::default(),
            plugin_dir: plugin_dir.as_ref().to_path_buf(),
            next_id: AtomicUsize::new(0),
        }
    }
    pub fn load_all_plugins(&mut self) -> std::io::Result<()> {
        for entry in std::fs::read_dir(&self.plugin_dir)? {
            let path = entry?.path();
            if path.extension().is_some_and(|ext| ext == "zip") {
                unsafe {
                    self.load_plugin(&path)?;
                }
            }
        }
        Ok(())
    }
    pub fn get_routes_json(&self) -> String {
        let routes = self.routes.read().unwrap();
        serde_json::to_string_pretty(&*routes).unwrap()
    }
    pub fn get_plugins_meta(&self) -> Vec<PluginMeta> {
        let plugins = self.plugins.read().unwrap();
        let routes = self.routes.read().unwrap();
        plugins
            .values()
            .map(|entry| {
                let plugin = &entry.plugin;
                let sig = plugin.signature();

                PluginMeta {
                    id: entry.id,
                    name: plugin.name().into(),
                    version: plugin.version().into(),
                    description: plugin.description().into(),
                    scope: plugin.scope().clone(),
                    signature: sig,
                    routes: routes.get(&plugin.scope()).cloned().unwrap_or_default(),
                    frontend: plugin.frontend_file(),
                }
            })
            .collect()
    }
    pub unsafe fn load_plugin(&mut self, path: &Path) -> std::io::Result<()> {
        let temp_dir = tempfile::tempdir()?;
        let temp_path = temp_dir.path();
        let file = std::fs::File::open(path)?;
        let mut archive = zip::ZipArchive::new(file)?;
        archive.extract(temp_path)?;

        let lib_path = walkdir::WalkDir::new(temp_path)
            .into_iter()
            .filter_map(Result::ok)
            .find(|e| {
                e.path()
                    .extension()
                    .is_some_and(|ext| ext == "dylib" || ext == "so" || ext == "dll")
            })
            .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, "No lib file found"))?
            .path()
            .to_path_buf();

        let library = libloading::Library::new(lib_path).map_err(|e| {
            std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("Failed to load library: {}", e),
            )
        })?;
        let creator: libloading::Symbol<PluginCreate> =
            library.get(b"_create_plugin").map_err(|e| {
                std::io::Error::new(
                    std::io::ErrorKind::Other,
                    format!("Failed to load symbol: {}", e),
                )
            })?;
        let raw = creator();
        let plugin = Box::from_raw(raw);
        let name = plugin.name().to_string();
        let plugin_dir = self.plugin_dir.join(&name);
        if plugin_dir.exists() {
            std::fs::remove_dir_all(&plugin_dir)?;
        }
        std::fs::rename(temp_path, &plugin_dir)?;
        let scope = plugin.scope();
        let routes: Vec<String> = plugin
            .register_routes()
            .iter()
            .map(|(path, _)| path.into())
            .collect();
        if self.routes.write().unwrap().contains_key(&scope) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::AlreadyExists,
                format!("Duplicate scope: {}", scope),
            ));
        }
        self.routes.write().unwrap().insert(scope, routes);
        let id = self.next_id.fetch_add(1, Ordering::SeqCst);
        if self.plugins.write().unwrap().contains_key(&name) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::AlreadyExists,
                format!("Duplicate plugin: {}", name),
            ));
        }
        self.plugins.write().unwrap().insert(
            name,
            PluginEntry {
                plugin,
                library,
                id,
            },
        );
        Ok(())
    }
    pub fn configure_routes(&self, cfg: &mut web::ServiceConfig) {
        let plugins = self.plugins.read().unwrap();
        for entry in plugins.values() {
            let scope_path = entry.plugin.scope();
            cfg.service(web::scope(&scope_path).configure(|app| {
                for (path, route_factory) in entry.plugin.register_routes() {
                    app.service(web::resource(&path).route(route_factory()));
                }
            }));
            // 註冊 /plugin/<插件名> 路由
            // if let Some(file_name) = entry.plugin.frontend_file() {
            if entry.plugin.frontend_file().is_some() {
                // let plugin_name = entry.plugin.name().to_string();
                // let file_path = format!("/plugin/{}", plugin_name);
                // let plugin_dir = format!("plugins/{}", plugin_name);
                // cfg.service(web::resource(&file_path).to(move |_req: HttpRequest| {
                //     let plugin_dir = plugin_dir.clone();
                //     let file_name = file_name.clone();
                //     async move {
                //         let file_path = format!("{}/frontend/assets/{}", plugin_dir, file_name);
                //         actix_files::NamedFile::open_async(&file_path)
                //             .await
                //             .map(|file| file.into_response(&_req))
                //             .unwrap_or_else(|_| {
                //                 actix_web::HttpResponse::NotFound().body("File not found")
                //             })
                //     }
                // }));
                let plugin_name = entry.plugin.name().to_string();
                let route_path = format!("/plugin/{}", plugin_name);
                let assets_path = format!("plugins/{}/frontend/assets", plugin_name);
                cfg.service(actix_files::Files::new(&route_path, assets_path));
            }
        }
    }
    #[allow(unused)]
    pub fn get_plugin_info(&self, name: &str, field: &str) -> Option<String> {
        let plugins = self.plugins.read().unwrap();
        plugins.get(name).map(|entry| match field {
            "name" => entry.plugin.name().to_string(),
            "version" => entry.plugin.version().to_string(),
            "description" => entry.plugin.description().to_string(),
            "scope" => entry.plugin.scope(),
            _ => "Unknown".to_string(),
        })
    }
}

impl Drop for PluginManager {
    fn drop(&mut self) {
        let mut plugins = self.plugins.write().unwrap();
        plugins.clear();
        let mut routes = self.routes.write().unwrap();
        routes.clear();
    }
}
